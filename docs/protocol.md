# LOKI: CVPN Wire-Format v1

## Geltungsbereich

Eine Sitzung verbindet genau einen Laptop (Initiator) mit einem Server
(Responder). Der äußere Transport ist UDP über IPv4. Beide Seiten kennen
vorher ihre CA, die erlaubte Zertifikatsidentität der Gegenstelle und ihre
Tunneladressen. Es gibt keine automatische Adressvergabe.

## Kryptografischer Transport

CVPN-Datensätze werden ausschließlich als DTLS-Anwendungsdaten übertragen.
Die Implementierung akzeptiert genau DTLS 1.2 und die Cipher-Suites
`ECDHE-ECDSA-AES256-GCM-SHA384` sowie `ECDHE-ECDSA-AES128-GCM-SHA256`.
OpenSSL übernimmt den Schlüsselaustausch, Verschlüsselung, Authentifizierung,
DTLS-Datensatznummern und deren Replay-Fenster. Sitzungscache und Tickets sind
abgeschaltet. Der Sitzungswechsel erfolgt über einen vollständigen neuen
Handshake, nicht über TLS-Renegotiation.

Beide Zertifikatsketten müssen zur konfigurierten CA führen. Zusätzlich wird
der vollständige DNS-SAN-Name der Gegenstelle geprüft, ohne Wildcards und
ohne Ausweichen auf den Common Name. Der Server verlangt ein Clientzertifikat.
Die erzeugten Zertifikate besitzen getrennte Zwecke `serverAuth` und `clientAuth`.

Vor dem Server-Handshake prüft `DTLSv1_listen` ein Cookie. Das Cookie besteht aus
einem vier Byte großen Zeitfenster und einem HMAC-SHA256 über Client-IPv4,
UDP-Quellport und Zeitfenster. Die Prüfung akzeptiert das aktuelle und vorherige
Minutenfenster. Der HMAC-Schlüssel wird beim Prozessstart zufällig erzeugt.
Nach erfolgreicher Cookie-Prüfung wird der UDP-Socket mit der Gegenstelle
verbunden, bevor der Handshake fortgesetzt wird.

## Anwendungsdatensatz

Genau ein CVPN-Datensatz wird mit einem `SSL_write_ex` als ein
DTLS-Anwendungsdatensatz gesendet. Ein empfangener Anwendungsdatensatz muss
genau einen vollständigen CVPN-Datensatz enthalten; nachlaufende Bytes und
verkürzte Payloads sind ungültig.

Alle mehrbyteigen Zahlen im CVPN-Format sind vorzeichenlos in Network Byte Order.
Der komplette CVPN-Header liegt innerhalb des verschlüsselten und
authentifizierten DTLS-Datensatzes.

| Offset | Bytes | Bedeutung |
| --- | --- | --- |
| 0 | 4 | ASCII `CVP1`: Protokoll und Hauptversion |
| 4 | 1 | Typ: HELLO=1, DATA=2, CLOSE=3 |
| 5 | 1 | Reserviert, muss null sein |
| 6 | 2 | Payload-Länge ohne acht Byte Header |
| 8 | variabel | Payload |

Unbekannte Versionen, Typen, reservierte Bits und inkonsistente Längen führen
zum Ende der authentifizierten Sitzung. Der Parser unterstützt bis zu 9000 Byte
Payload; die Sitzung begrenzt DATA zusätzlich auf die konfigurierte innere MTU,
standardmäßig 1280 Byte.

## HELLO (Typ 1)

Die Payload ist genau zehn Byte groß:

| Offset in Payload | Bytes | Bedeutung |
| --- | --- | --- |
| 0 | 4 | Tunnel-IPv4 des Senders |
| 4 | 4 | Erwartete Tunnel-IPv4 des Empfängers |
| 8 | 2 | Konfigurierte innere MTU, standardmäßig 1280 |

Der Empfänger prüft beide Adressen und die MTU gegen seine lokale
Konfiguration. Erst nach einem gültigen HELLO werden DATA-Pakete zugelassen.
Beide Seiten senden HELLO unabhängig: zunächst im Sekundentakt, nach dem
Empfang des ersten gültigen HELLO alle fünf Sekunden. Damit wird ein verlorenes
HELLO erneut gesendet, und es existiert auch ohne Nutzverkehr ein Lebenszeichen.
Es gibt keine verlässliche Zustellung von Anwendungsdatensätzen und kein
ausgehandeltes Erweiterungsformat in Version 1.

Beispiel für einen Laptop mit Adresse 10.203.0.2, Server 10.203.0.1 und MTU 1280:

```text
43 56 50 31 01 00 00 0a 0a cb 00 02 0a cb 00 01 05 00
```

## DATA (Typ 2)

Die Payload enthält genau ein IPv4-Paket von 20 Byte bis zur eingestellten
inneren MTU. Ein inneres IPv4-Fragment ist ebenfalls ein gültiges IP-Paket.
Version, Headerlänge und IPv4-Gesamtlänge werden geprüft. IPv4-Header und
Transport-Prüfsummen prüft bei der Weiterleitung zusätzlich der Linux-Kernel.
Der Parser ersetzt keine Kernelprüfung.

Der Server akzeptiert vom Laptop nur Pakete mit dessen konfigurierter
Tunnel-Quelladresse. Der Laptop akzeptiert vom Server nur Pakete mit seiner
eigenen Tunnel-Zieladresse. In Gegenrichtung werden die entsprechenden
Adressen vor dem Verschlüsseln geprüft. So darf der Client über seine
authentifizierte Sitzung keine andere innere Quelladresse verwenden.

Der äußere Link-MTU-Grenzwert ist innere MTU plus 80 Byte: standardmäßig
1280 + 80 = 1360 Byte. Nach dem Handshake prüft die Implementierung, ob
`DTLS_get_data_mtu` mindestens innere MTU plus acht Byte CVPN-Header erlaubt,
also standardmäßig 1288 Byte. Die 80 Byte sind Reserve für CVPN, DTLS, UDP
und den äußeren IPv4-Header. Mit den angebotenen AES-GCM-Suites betragen
diese zusammen 73 Byte, ein inneres 1280-Byte-Paket damit außen 1353 Byte.

Der UDP-Socket setzt `IP_PMTUDISC_DO`, wodurch äußere IP-Fragmentierung
unterbunden wird. Eine kleinere entdeckte äußere Path-MTU kann den Versand
mit `EMSGSIZE` scheitern lassen; die innere MTU wird derzeit nicht automatisch
nachgeregelt. `--mtu` ist dann passend niedriger einzustellen, bleibt aber mindestens 1280.
Der konfigurierte äußere Mindestgrenzwert ist folglich 1360. Ein kleinerer
äußerer Pfad wird in dieser Version nicht unterstützt.

Innen setzt CVPN das DF-Bit nicht um. Beim Forwarding auf die TUN-Schnittstelle
meldet Linux für zu große IPv4-Pakete mit DF per ICMP Typ 3/Code 4 die
TUN-MTU an den Sender zurück. Ohne DF darf Linux innere IPv4-Pakete fragmentieren.
Eine eigene Fragmentierungs- oder Reassemblierungsschicht im CVPN-Protokoll
gibt es nicht. Bei einem kleineren Internetpfad in Gegenrichtung leitet der
Server die zugehörige ICMP-Meldung nach der NAT-Zuordnung durch den Tunnel
zum Client zurück. Der Client kann so eine kleinere PMTU für das konkrete
Internet-Ziel lernen, ohne seine TUN-MTU unter 1280 zu setzen. Dieses Verhalten folgt [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html#section-4).

## CLOSE (Typ 3)

Ein authentifizierter CLOSE-Datensatz hat eine leere Payload und beendet die
aktuelle Sitzung. Die Nachricht ist eine bestmögliche Benachrichtigung über UDP;
bei Verlust beendet die Gegenstelle die Sitzung spätestens über ihren
Inaktivitäts-Timer. Netzwerkrouten und Client-Ausgabesperre bleiben bestehen.

## Zustände und Grenzen

1. Unverbundener UDP-Socket, serverseitige Cookie-Prüfung
2. Verbundener UDP-Socket, gegenseitig authentifizierter DTLS-Handshake
3. HELLO austauschen und konfigurierte Tunnelparameter prüfen
4. DATA weiterleiten und HELLO als Lebenszeichen senden
5. Bei Fehler, CLOSE, Inaktivität oder Sitzungsgrenze neu verbinden

Handshake-Versuche sind auf zwölf Sekunden begrenzt. Nach 15 Sekunden ohne
gültigen Anwendungsdatensatz endet eine Sitzung. Ungültige innere IP-Pakete
werden verworfen und gelten nicht als Lebenszeichen. Die Sitzungsgrenzen
betragen 30 Minuten oder 1.048.576 gesendete Anwendungsdatensätze.
`--session-seconds` kann das Zeitlimit für Tests auf mindestens fünf Sekunden
verkürzen, aber nicht über 30 Minuten verlängern.

Ein gültiger Client belegt den einzigen Verbindungsplatz. Automatisches Roaming,
mehrere Clients, IPv6-Nutzdaten, Zertifikatswiderruf und Wiederaufnahme alter
Sitzungen gehören nicht zu Version 1.

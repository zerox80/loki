# Nativer Betrieb auf Linux

Diese erste Version verbindet einen Linux-Laptop mit einem Linux-Server.
IPv4-Verkehr geht über eine TUN-Schnittstelle, einen authentifizierten
UDP-Tunnel und NAT auf dem Server ins Internet. Die Laptop-Konfiguration
blockiert direkten IPv4-Verkehr und IPv6 außerhalb des Tunnels. Die Sperre
bleibt bei einem Absturz oder Verbindungsabbruch aktiv.

Der Tunnelkern und das eigene Paketformat sind in C implementiert. OpenSSL
übernimmt DTLS 1.2, ECDHE, AES-GCM, Zertifikatsprüfung und den Schutz vor
wiederholten DTLS-Datensätzen. Python-Helfer richten Zertifikate und die
Linux-Netzwerkkonfiguration ein. Die [Protokollspezifikation](protocol.md)
beschreibt die genaue Aufteilung.

**Stand: Entwicklungsprototyp v0.2.** Der getestete Umfang ist weiter unten
aufgeführt. Für den späteren Alltagseinsatz fehlen insbesondere die Anpassung
an wechselnde WLAN-/Mobilfunk-Uplinks, automatische Zertifikatserneuerung
und eine unabhängige Prüfung. Native IPv6-Tunnelung und
mehrere gleichzeitig verbundene Clients sind noch nicht implementiert.

## Voraussetzungen und Build

- Linux mit TUN, Netzwerk-Namespaces und nftables
- C11-Compiler, Make, pkg-config, OpenSSL-Entwicklungsdateien ab Version 3.0
- Python 3, `ip`, `nft`, `openssl`
- Für die automatische DNS-Konfiguration: laufendes systemd-resolved und `resolvectl`
- Für die Integrationstests zusätzlich: `curl`, `ping`, `unshare`, `nsenter`, `setpriv`

Im Projektverzeichnis:

```sh
make
make test
make integration
```

`make integration` baut drei voneinander und vom normalen Rechnernetz
getrennte Netzwerk-Namespaces auf. Die Testadresse stellt einen lokalen
Internetdienst dar; der Test benötigt keinen externen Server und keinen
Internetzugriff. Auch die Zertifikate für den Test werden nur temporär erzeugt.
Benutzer-Namespaces müssen auf dem Testrechner erlaubt sein.

## Schlüssel und Zertifikate

Einmal auf einem vertrauenswürdigen Rechner ausführen; das Zielverzeichnis
darf noch nicht existieren:

```sh
python3 tools/keygen.py /pfad/zu/privatem-pki-verzeichnis
```

Das Skript erzeugt eine private CA sowie je ein P-256-Zertifikat mit dem
passenden Verwendungszweck und SAN-Namen:

| Ziel | Benötigte Dateien | Erwartete Gegenstelle |
| --- | --- | --- |
| Server | `ca.pem`, `server.pem`, `server.key` | `client.cvpn` |
| Laptop | `ca.pem`, `client.pem`, `client.key` | `server.cvpn` |

Die Dateien auf die jeweiligen Rechner übertragen. Private Schlüssel bleiben
mit Dateirechten `0600` beim jeweiligen Daemon-Benutzer. `ca.key` separat und
offline aufbewahren; der laufende Tunnel benötigt diesen Schlüssel nicht.
Die Endzertifikate gelten ein Jahr. Eine Erneuerung ist in dieser Version manuell.

Der Name `server.cvpn` ist eine Zertifikatsidentität. Eine öffentliche
DNS-Auflösung dieses Namens ist nicht erforderlich; der Transport verwendet
die separat konfigurierte numerische IPv4-Adresse des Servers.

## Server starten

Das folgende Beispiel nimmt an, dass die drei Server-Dateien im Unterordner
`server-keys` liegen. `eth0` durch die tatsächliche Internet-Schnittstelle ersetzen.
Der Netzwerkhelfer richtet eine persistente TUN-Schnittstelle für die aktuelle
Benutzer-ID, Weiterleitung und NAT ein. Der C-Prozess läuft anschließend ohne sudo.
Die Weiterleitung wird gezielt auf TUN und WAN aktiviert; der globale
`ip_forward`-Schalter bleibt unverändert, da dessen Umschalten
[weitere IPv4-Einstellungen zurücksetzen kann](https://docs.kernel.org/networking/ip-sysctl.html).

```sh
sudo python3 tools/network.py server-up --wan eth0 --owner "$(id -u)" --mtu 1280
./build/loki server --endpoint 0.0.0.0 --tun cvpn0 --mtu 1280 \
  --cert server-keys/server.pem --key server-keys/server.key \
  --ca server-keys/ca.pem --peer-name client.cvpn
```

UDP-Port 4433 muss auch in einer bestehenden Host- oder Cloud-Firewall erlaubt
sein. Eine bestehende Forwarding-Firewall muss die Weiterleitung zwischen
`cvpn0` und der Internet-Schnittstelle erlauben. Der Helfer verwaltet nur seine
eigenen nftables-Tabellen; deren Accept-Regeln überschreiben keine Drop-Regeln
anderer Basisketten.

Die feste Tunneladressierung ist Server `10.203.0.1/30`, Laptop `10.203.0.2/30`,
standardmäßig innere MTU 1280 und äußeres MTU-Limit 1360. Bei einer Überschneidung mit einem vorhandenen Interface bricht der
Helfer vor der Einrichtung ab.

## Laptop starten

`198.51.100.10` ist eine Dokumentationsadresse und muss durch die echte
Server-Adresse ersetzt werden. Die Dateien liegen in diesem Beispiel in
`client-keys`. Diese Befehle verändern die Netzwerkkonfiguration des Laptops.

```sh
LOKI_SERVER_IPV4=198.51.100.10
sudo python3 tools/network.py client-up \
  --endpoint "$LOKI_SERVER_IPV4" --owner "$(id -u)" --mtu 1280
./build/loki client --endpoint "$LOKI_SERVER_IPV4" --tun cvpn0 --mtu 1280 \
  --cert client-keys/client.pem --key client-keys/client.key \
  --ca client-keys/ca.pem --peer-name server.cvpn
```

Der Helfer aktiviert zuerst die Ausgabesperre. Er erlaubt Loopback, IPv4 durch
`cvpn0` und UDP zur Server-Adresse auf Port 4433 für die angegebene Benutzer-ID.
IPv6 außerhalb von Loopback bleibt gesperrt. Danach richtet er eine eigene
IPv4-Routingtabelle (51899, Regelpriorität 11100) ein. Eine spezifische Route
hält den verschlüsselten Transport zum Server auf dem bisherigen Uplink.

DNS wird über systemd-resolved auf `cvpn0` mit Routing-Domain `~.` gesetzt.
Standardresolver ist `1.1.1.1`; mit `--dns IPV4` ist ein anderer Resolver möglich.
Direkte DNS-Pakete über den Uplink werden von der Ausgabesperre blockiert.
Die resolved-Integration muss auf dem jeweiligen Zielsystem geprüft werden;
der isolierte Integrationstest verwendet bewusst den manuellen DNS-Modus,
damit er keinen Dienst des normalen Rechners umkonfiguriert.

Ohne systemd-resolved kann `--dns-mode manual` verwendet werden. Dann muss
die lokale Resolver-Konfiguration selbst auf einen über den Tunnel erreichbaren
DNS-Dienst zeigen. Die Ausgabesperre bleibt auch in diesem Modus aktiv.

Bei einem Netzwechsel die Konfiguration kontrolliert neu einrichten. Die
physische Route zum Server wird in v0.2 beim Setup ermittelt und danach
nicht automatisch an einen neuen Uplink angepasst. Direkte LAN-Verbindungen
werden durch diese Full-Tunnel-Konfiguration ebenfalls gesperrt.

## MTU, Nutzdaten und Fragmentierung

`--mtu 1280` ist die MTU des inneren IP-Pakets und des TUN-Interfaces.
Das äußere MTU-Limit für DTLS wird automatisch als `1280 + 80 = 1360`
berechnet. Die 80 Byte sind Reserve für die Kapselung, keine zusätzlichen
Nutzdaten und keine obligatorischen Füllbytes.

Im aktuellen IPv4-/AES-GCM-Format benötigt ein inneres IP-Paket von 1280 Byte
außen 1353 Byte: acht Byte CVPN, 37 Byte DTLS, acht Byte UDP und 20 Byte IPv4
kommen hinzu. Es bleibt damit unter dem äußeren Limit von 1360 Byte.
Die MTU des physischen Interfaces wird vom Helfer nicht verändert; sie muss
mindestens das äußere Budget erlauben. Eine kleinere MTU weiter auf dem
Internetpfad bleibt möglich und erfordert eine entsprechend kleinere
`--mtu`-Einstellung innerhalb des Bereichs 1280..9000. Reicht der äußere Pfad
für die Mindestkonfiguration nicht aus, wird er derzeit nicht unterstützt.
Automatische Anpassung der inneren MTU ist noch nicht implementiert.

Die Einstellung ist im C-Daemon und im Netzwerkhelfer auf beiden Seiten
gleich zu verwenden. Der Standard ist jeweils 1280. Für den derzeitigen
IPv4-Betrieb sind Werte von 1280 bis 9000 erlaubt, sofern der Uplink das
um 80 Byte größere äußere Budget unterstützt. Abweichende Peer-MTUs oder
ein TUN-Interface mit anderer MTU werden abgewiesen.

Der äußere UDP-Socket verwendet `IP_MTU_DISCOVER=IP_PMTUDISC_DO`: Das
DF-Bit ist gesetzt, äußere IP-Fragmentierung ist damit nicht erlaubt.
Innen bleibt das normale IPv4-Verhalten erhalten. Ein zu großes Paket
mit DF wird verworfen, und der Linux-Kernel meldet dem Sender per
ICMP Typ 3/Code 4 die nächste MTU, hier 1280. Ohne DF darf der Kernel
fragmentieren; beim Empfänger werden die inneren Fragmente wieder zusammengesetzt.
Bestehende Firewalls müssen die erforderlichen ICMP-PMTU-Nachrichten zulassen.
Siehe [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html#section-4).

Für TCP kündigt der lokale Netzwerkstack anhand der TUN-MTU eine passende
MSS an. MTU 1280 ergibt ohne zusätzliche Optionen maximal 1240 Byte
TCP-Nutzdaten über IPv4. Die Interface-MTU bleibt dabei 1280.
Bei künftigem innerem IPv6 wären es 1220 Byte TCP-Nutzdaten bei derselben
MTU 1280. IPv6 erfordert eine Link-MTU von mindestens 1280; IPv6-Weiterleitung
ist in diesem Prototyp weiterhin nicht implementiert. Die 80-Byte-Reserve
gilt für den aktuellen äußeren IPv4-Transport; äußerer IPv6-Transport
benötigt mit diesem DTLS-Format mehr Reserve.

## Beenden und Netzwerkkonfiguration zurücknehmen

Zuerst den jeweiligen C-Prozess mit `Ctrl+C` oder `SIGTERM` beenden.
Danach auf dem Laptop:

```sh
sudo python3 tools/network.py client-down
```

Auf dem Server:

```sh
sudo python3 tools/network.py server-down
```

Der Laptop-Helfer nimmt DNS und die eigenen Routen zurück und entfernt die
TUN-Schnittstelle. Erst danach hebt er die Ausgabesperre auf. Diese explizite
Aktion gibt den normalen Internetzugang wieder frei. Ein beendeter oder
abgestürzter VPN-Prozess allein hebt die Sperre nicht auf.

Bei einem Setup-Fehler bleibt ein vorhandener Zwischenstand dokumentiert unter
`/run/cvpn-client` beziehungsweise `/run/cvpn-server`. Mit dem passenden
`*-down`-Befehl lässt sich auch eine teilweise Einrichtung zurücknehmen.
Ein anderes Zustandsverzeichnis ist mit `--state-dir VERZEICHNIS` möglich;
dasselbe Verzeichnis muss bei Up und Down verwendet werden.

## Verhalten bei Verbindungsabbrüchen

Jede Seite sendet regelmäßig einen authentifizierten HELLO-Datensatz.
Nach 15 Sekunden ohne gültige Nachrichten wird die Sitzung beendet. Der
Client versucht anschließend eine neue Verbindung. Nach spätestens 30 Minuten
oder 1.048.576 gesendeten Datensätzen wird ebenfalls eine neue DTLS-Sitzung
mit frischem ECDHE-Schlüsselaustausch aufgebaut. In dieser Version kann dabei
eine kurze Verkehrsunterbrechung entstehen. Die persistente Schnittstelle,
Routen und Ausgabesperre bleiben bestehen.

CVPN transportiert IPv4-Pakete als Datagramme. Verlorene Datenpakete werden
vom VPN nicht erneut übertragen; enthaltene TCP-Verbindungen übernehmen ihre
eigene Wiederholung. DTLS wiederholt die notwendigen Handshake-Nachrichten.

## Prüfung des Entwicklungsstands

Der Test verwendet die realen C-Prozesse und echte TUN-Geräte. Er kontrolliert:

- Ablehnung falscher Server- und Client-SAN-Namen sowie einer fremden CA
- Betrieb des C-Daemons ohne Linux-Capabilities nach der Einrichtung
- HTTP, UDP und ICMP durch den Tunnel und Austritt über Server-NAT
- IPv4-Pakete bis zur festgelegten MTU
- Konfigurierbare innere MTU mit 80 Byte äußerer Reserve und Prüfung von Uplink/Peer/TUN
- Äußeres DF, keine äußeren IP-Fragmente und Einhaltung des 1360-Byte-Limits
- ICMP-Rückmeldung mit MTU 1280 an einen externen Sender, dessen verkleinerte
  Antwort anschließend ankommt, sowie innere IPv4-Reassemblierung ohne DF
- ICMP-Rückmeldung bei kleinerem Internetpfad in Gegenrichtung durch den Tunnel
  zum Client; dessen Kernel lernt die kleinere Ziel-PMTU bei unveränderter TUN-MTU
- Gesperrten Direktverkehr vor dem Verbindungsaufbau und bei Serverausfall
- Blockierten direkten IPv6-Verkehr
- Wiederverbindung nach Server-Neustart und nach einem Sitzungswechsel
- Wiederholte echte DTLS-Datagramme sowie manipulierte Chiffrate mit gültiger
  UDP-Prüfsumme und gefälschter hoher Datensatznummer
- Rücknahme der Netzwerkkonfiguration und Wiederherstellung der ursprünglichen Route

Ein zusätzlicher C-Test prüft das Wire-Format, fehlerhafte Längen, Typen,
Versionen und IPv4-Header sowie 50.000 generierte Parser-Eingaben.
Die konkreten Ergebnisse dieser Auslieferung stehen in [Validierung](validation.md).

## Technische Grundlagen

- [Linux: TUN/TAP-Schnittstelle](https://docs.kernel.org/networking/tuntap.html)
- [OpenSSL: DTLSv1_listen und Cookie-Prüfung](https://docs.openssl.org/3.5/man3/DTLSv1_listen/)
- [OpenSSL: maximaler DTLS-Anwendungsdatensatz](https://docs.openssl.org/3.5/man3/DTLS_get_data_mtu/)

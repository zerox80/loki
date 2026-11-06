# Validierung vom 6. November 2026

## Umgebung

Die dokumentierten Builds und Netzwerktests wurden nach der Aufteilung in
Module erneut ausgeführt. Der C-Datenpfad bleibt zum bisherigen Wire-Format kompatibel.

Linux, GCC 16.2.1, Clang 22.1.8, OpenSSL 3.5.9, Python 3.14.8.
Es wurden die unveränderten Systembibliotheken von OpenSSL verwendet.

## Durchgeführte Prüfungen

| Prüfung | Ergebnis |
| --- | --- |
| GCC-Build mit C11, `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror` | bestanden |
| Clang-Build mit denselben Warnungen, AddressSanitizer und UndefinedBehaviorSanitizer | bestanden |
| Clang Static Analyzer für alle 15 C-Module | keine Diagnosen |
| C-Protokolltest einschließlich 50.000 generierter Eingaben | bestanden, auch unter ASan/UBSan |
| Vollständiger Namespace-Integrationstest mit den instrumentierten C-Daemons | bestanden |
| Python-Syntaxprüfung aller Helfer und Integrationstests | bestanden |
| Docker-Image-Build auf Linux mit Docker Engine 29.1.3 und Compose 2.40.3 | bestanden |
| Gegenseitige Authentifizierung von Compose-Container und nativem Client mit eigenen Test-TUNs | bestanden |
| Container ohne Capabilities, UID 1000, schreibgeschützte Rootfs und `NoNewPrivs=1` | bestanden |
| Wiederverwendung des bestehenden Host-TUN/NAT-Zustands durch den Compose-Helfer | bestanden |
| Auflösung der Compose-Konfiguration ohne erreichbaren Docker-Daemon | bestanden |

Der letzte Integrationstest lief mit
`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1` und
`UBSAN_OPTIONS=halt_on_error=1`. Es gab in den ausgeführten Tests keine
Sanitizer-Meldungen.

## Beobachtetes Verhalten im Integrationstest

1. Direkter IPv4- und IPv6-Verkehr funktionierte vor dem Setup.
2. Die Client-Ausgabesperre blockierte direkten IPv4- und IPv6-Verkehr
   bereits vor dem Aufbau einer VPN-Verbindung.
3. Ein falscher Server-SAN sowie ein falscher Client-SAN wurden jeweils mit
   einem Zertifikatsfehler wegen abweichender Identität zurückgewiesen.
4. Eine fremde CA führte zur Ablehnung der Gegenstelle.
5. Die echten C-Daemons liefen nach dem Setup mit geleerten Capability-Sätzen.
6. Eine vollständige HTTP-Antwort von 217.088 Byte, UDP-Echo und ICMP wurden
   durch den Tunnel übertragen. Der HTTP-Dienst sah die WAN-Adresse des
   Servers als Quelle und bestätigte damit die Weiterleitung mit NAT.
7. Ein inneres IPv4-Paket von genau 1280 Byte passierte den Tunnel. Ein
   lokales 1281-Byte-Paket mit DF wurde an der TUN-MTU abgewiesen.
8. Wiederholte echte DTLS-Anwendungsdatagramme führten nicht zu einer weiteren
   Zustellung an den UDP-Dienst. Vor der Raw-Paketinjektion wurde die
   UDP-Prüfsumme vollständig berechnet, um Offload-Artefakte auszuschließen.
9. Ein manipuliertes Chiffrat mit gültiger UDP-Prüfsumme und gefälschter hoher
   DTLS-Datensatznummer wurde nicht zugestellt. Eine folgende legitime
   Nachricht kam an; das gefälschte Paket verschob das Replay-Fenster nicht.
10. Der Klartextmarker der HTTP-Antwort erschien nicht in den erfassten äußeren
    UDP-Paketen.
11. Nach dem Beenden des Servers schlug ein neuer HTTP-Aufruf fehl. Nach dem
    Neustart verband sich der weiterlaufende Client erneut und übertrug die Antwort.
12. Ein für den Test auf fünf Sekunden verkürztes Sitzungslimit führte zu
    einem neuen authentifizierten Handshake und anschließendem Datenverkehr.
13. Server-Forwarding funktionierte gezielt pro Schnittstelle, während der
    globale IPv4-Forwarding-Schalter null blieb. Die vorherige WAN-Einstellung
    wurde beim Cleanup wiederhergestellt.
14. Nach explizitem Client-Cleanup funktionierte wieder die ursprüngliche
    direkte Route mit der ursprünglichen Client-WAN-Adresse als Quelle.
15. `--mtu 1280` führte zu TUN-MTU 1280 und äußerem Budget 1360. Ein Uplink
    mit MTU 1359 wurde vor dem Anlegen von Zustand/Firewall abgewiesen.
    Abweichende TUN- und Peer-MTUs wurden abgelehnt. Eine gleich konfigurierte
    innere MTU 1400 funktionierte ebenfalls mit echtem HTTP-Verkehr.
16. In den erfassten äußeren UDP-Paketen war DF gesetzt. Es gab keine äußeren
    IP-Fragmente und kein äußeres Paket größer als 1360 Byte. Für die innere
    MTU-Grenze wurde ein äußeres 1353-Byte-Paket beobachtet.
17. Ein externer UDP-Sender schickte eine 1281-Byte-Antwort mit DF über den
    NAT-Server zum Client. Der Sender empfing tatsächlich einen ICMP-Fehler
    vom Ursprung ICMP mit Typ 3, Code 4, `EMSGSIZE` und Next-Hop-MTU 1280.
    Sein Kernel lernte PMTU 1280. Eine anschließend auf insgesamt 1280 Byte
    verkleinerte Antwort wurde beim Client zugestellt.
18. Derselbe externe Sender konnte ohne DF eine 1281-Byte-Antwort schicken,
    die nach innerer Fragmentierung beim Client erfolgreich reassembliert wurde.
19. Der externe TCP-Dienst verwendete bei innerer MTU 1280 eine effektive MSS
    von höchstens 1240 Byte, bei innerer MTU 1400 höchstens 1360 Byte. Die
    TUN-MTU selbst blieb jeweils auf dem konfigurierten inneren Wert.

20. Bei einem Internetpfad mit MTU 1200 hinter dem Server empfing der Client
    durch den verschlüsselten Tunnel tatsächlich ICMP Typ 3/Code 4 mit
    `EMSGSIZE` und Next-Hop-MTU 1200. Sein Kernel lernte die Ziel-PMTU 1200.
    Ein kleineres UDP-Paket erreichte den Internetdienst anschließend über NAT;
    die innere TUN-MTU blieb 1280.

## Realer Laptop und Container-Test

Zusätzlich zum isolierten Netzwerktest wurde der Linux-Laptop mit dem eigenen
öffentlichen Ubuntu-Server verbunden. Ein HTTPS-Aufruf bestätigte den Austritt
über den Server; eine echte UDP-DNS-Abfrage, eine `resolvectl`-Abfrage über
`cvpn0` und ein HTTPS-Aufruf mit Status 204 funktionierten. Das ist eine
Funktionsprobe, kein Last- oder Dauertest.

Das modulare Image wurde auf einem Linux-Dockerhost aus dem mehrstufigen
Dockerfile gebaut. Der Build führte den C-Protokolltest aus. Ein getrenntes
Compose-Projekt mit temporären Zertifikaten und zwei eigenen TUNs bestätigte
beide Zertifikatsidentitäten, `Tunnel ready.`, TUN-Zugriff als UID 1000,
`CapEff=0`, `NoNewPrivs=1`, Host-Netzwerk und eine nur lesbare Rootfs.
Der Image-Test prüft Authentifizierung und Containerrechte; er behauptet
keinen Paketpfad zwischen zwei auf demselben Host lokalen IP-Adressen.
Dafür ist der separate Namespace-Test zuständig. Die temporären Container
und TUNs wurden anschließend entfernt.

## Grenzen der Aussage

Diese Ergebnisse belegen das Verhalten des beschriebenen Prototyps in
isolierten lokalen Netzwerken. Sie sind keine unabhängige Sicherheitsprüfung
und kein Dauer- oder Lasttest im öffentlichen Internet. Der isolierte
Namespace-Test verwendet den manuellen DNS-Modus; die reale
systemd-resolved-Integration wurde separat auf dem Laptop geprüft. Roaming,
native IPv6-Tunnelung, Zertifikatserneuerung und mehrere Clients gehören
noch nicht zum implementierten Umfang.

## Wiederholen

Im Projektverzeichnis:

```sh
make test
make integration
```

Für die instrumentierte Variante einen separaten Build-Pfad verwenden:

```sh
make CC=clang BUILD=build-sanitized \
  CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined' all test
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/integration/network.py --binary build-sanitized/loki --work-dir build-sanitized/test-work
```

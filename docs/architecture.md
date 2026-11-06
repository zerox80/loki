# Architektur

Der C-Prozess öffnet ein vorbereitetes, dem Daemon-Benutzer gehörendes TUN.
Er ändert weder Routen noch Firewall oder DNS. Diese Aufgaben erledigen die
Python-Module vor dem Start mit Root-Rechten. Anschließend benötigt der
Datenpfad keine Linux-Capabilities.

| Modul | Verantwortung |
| --- | --- |
| `app` | Optionen prüfen, Ressourcen öffnen, Wiederverbindung steuern |
| `platform/linux` | Existenz, Adresse und MTU des TUN prüfen und es öffnen |
| `transport` | nicht blockierende UDP-Sockets, Peer-Verbindung, äußeres DF |
| `crypto/context` | DTLS 1.2, Cipher-Suites, Zertifikate und SAN-Prüfung |
| `crypto/cookie` | kurzlebige HMAC-Cookies vor dem Server-Handshake |
| `crypto/handshake` | Cookie-Listen, Socket an Peer binden, Handshake-Deadline |
| `crypto/io` | DTLS-Timer, Polling und Versand vollständiger Records |
| `protocol` | Wire-Format, Längen, Typen, IPv4-Grenzen, HELLO und MTU |
| `session` | HELLO-Zustand, TUN↔DTLS, Adressbindung, Zeit-/Record-Limits |
| `runtime` | monotone Zeit und Signale |
| `tools/cvpn_network` | Client-Routen/DNS/Sperre, Server-NAT/Forwarding, Cleanup |
| `tools/compose.py` | gleiche Compose-Konfiguration für Image und Host-TUN |

Der Projektname ist LOKI. Das bereits getestete Wire-Format heißt weiterhin
CVPN v1 mit Magic `CVP1`; Zertifikatsidentitäten `server.cvpn`/`client.cvpn`,
TUN-Vorgabe `cvpn0` und die eigenen nftables-Namen bleiben kompatibel mit dem
vorherigen Prototyp. Der neue Programmname ist `loki`.

Die Module haben konkrete Aufgaben. Kryptografie wird über OpenSSL verwendet;
es gibt keine eigene AES-, Assembler- oder Zufallszahlenimplementierung.
Verlorene DATA-Records werden vom VPN nicht erneut gesendet. DTLS übernimmt
Handshake-Wiederholungen, enthaltenes TCP seine eigenen Übertragungsfehler.

Netzwerkzustand liegt unter `/run/cvpn-client` beziehungsweise `/run/cvpn-server`.
Der Client-Helfer installiert seine Ausgabesperre zuerst und entfernt sie beim
expliziten Cleanup zuletzt. Eine persistente TUN-Schnittstelle bleibt bestehen,
wenn der C-Prozess stirbt. Ein kontrollierter Sitzungswechsel sendet bestmöglich
ein DTLS `close_notify`, damit der einzige Verbindungsplatz zügig frei wird.

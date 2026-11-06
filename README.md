# LOKI VPN

Ein eigenes VPN für Linux in C: Laptop → UDP/DTLS → eigener Server → Internet.
Der Client verwendet TUN, DNS über systemd-resolved und eine Ausgabesperre,
die bei einem Tunnelabbruch aktiv bleibt. Der Server kann nativ oder mit
Docker Compose laufen. Die Verschlüsselung übernimmt OpenSSL 3.

**Entwicklungsprototyp:** ein Client, innerer und äußerer IPv4-Verkehr.
Native IPv6-Tunnelung, Roaming und automatische Zertifikatserneuerung fehlen
noch. Die Integrationstests ersetzen keine unabhängige Sicherheitsprüfung.

## Projektstruktur

```text
include/cvpn/           öffentliche Schnittstellen des C-Kerns
src/
  app/                 Programmstart und Kommandozeilenoptionen
  crypto/              DTLS-Kontext, Cookies, Handshake und Record-I/O
  platform/linux/      TUN-Zugriff und Prüfung der Interface-Konfiguration
  protocol/            Frame-Codec, HELLO, IPv4-Prüfung und MTU-Grenzen
  runtime/             monotone Uhr und Signalbehandlung
  session/             Tunnelzustand, Paketweiterleitung und Sitzungswechsel
  transport/           UDP-Sockets und äußeres DF
tools/
  cvpn_network/        getrennte Host-Module für Client, Server und Cleanup
  network.py           Einstieg für TUN, Routing, DNS, NAT und Firewall
  compose.py           Compose-Build und Host-Vorbereitung
  keygen.py            private CA und Zertifikate
  live_client.py       Laptop-Teststart mit automatischem Fehler-Rollback
tests/
  unit/                C-Parser und Wire-Format
  integration/         echte TUN-/Namespace- und Container-Tests
deploy/
  docker/              mehrstufiges Dockerfile
  systemd/             optionale Host-Vorbereitung beim Boot
docs/                 Betrieb, Protokoll, Architektur und Testergebnisse
compose.yaml           Serverdienst
.env.example           Konfiguration ohne Geheimnisse
```

## Bauen und testen

Benötigt werden Linux, C11, Make, pkg-config, OpenSSL-Entwicklungsdateien ab
Version 3.0 und Python 3. Für die Netzwerktests zusätzlich `ip`, `nft`, `curl`,
`ping`, `unshare`, `nsenter` und `setpriv` sowie erlaubte User-Namespaces.

```sh
make -j4
make test
make integration
```

Das Programm liegt anschließend unter `build/loki`. Die Netzwerktests laufen
isoliert vom normalen Rechnernetz und benötigen keinen öffentlichen Server.

## Server mit Docker Compose

Auf einem Linux-Server mit rootful Docker Engine, Compose v2, Python 3,
`iproute2` und `nftables`:

```sh
cp .env.example .env
# .env bearbeiten: WAN-Interface, Schlüsselverzeichnis und Daemon-UID/GID setzen.
sudo python3 tools/compose.py up
sudo python3 tools/compose.py logs
```

Der Helfer baut das Image, erstellt das TUN für die konfigurierte UID und
richtet gezielt Forwarding und NAT ein. Der Container läuft danach ohne
Linux-Capabilities als diese UID. Das Schlüsselverzeichnis wird nur lesbar
eingebunden. Im Image und in `.env` liegen keine privaten Schlüssel.

Die vollständige Einrichtung einschließlich Zertifikaten, Firewall,
Image-Export und Boot-Verhalten steht in [Docker Compose](docs/compose.md).
Der Laptop läuft nativ; seine Einrichtung steht in [Linux-Betrieb](docs/native.md).

## MTU und PMTU

- **TUN mindestens 1280**, standardmäßig 1280 Byte.
- **Äußeres Budget = TUN + 80**, mindestens und standardmäßig 1360 Byte.
- Die 80 Byte sind Kapselungsreserve. Ein inneres 1280-Byte-Paket benötigt mit
  dem aktuellen IPv4-/AES-GCM-Format tatsächlich 1353 Byte außen.
- Außen ist DF gesetzt, äußere IP-Fragmentierung ist ausgeschaltet.
- Innen bleibt normales IPv4-Verhalten erhalten: ICMP Typ 3/Code 4 bei DF,
  Fragmentierung und Reassemblierung ohne DF.
- PMTU-Rückmeldungen funktionieren in beide Richtungen. Eine kleinere
  Ziel-PMTU hinter dem Server ändert die TUN-MTU nicht.

Eine äußere Route, die die Mindestkonfiguration nicht tragen kann, wird in
dieser Version nicht unterstützt. Automatische äußere MTU-Anpassung fehlt.

Weitere Details: [Protokoll](docs/protocol.md), [Architektur](docs/architecture.md),
[Validierung](docs/validation.md). Lizenz: [MIT](LICENSE).

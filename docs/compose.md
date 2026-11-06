# Server mit Docker Compose

## Voraussetzungen

Linux mit rootful Docker Engine und Compose v2, `/dev/net/tun`, Python 3,
`ip` und `nft`. Rootless Docker und Docker Desktop gehören nicht zum getesteten
Umfang. Der Laptop läuft nativ, damit sein DNS, seine Routen und die Sperre
gezielt auf dem tatsächlichen Rechner eingerichtet werden.

Docker verwendet den [Host-Netzwerkmodus](https://docs.docker.com/engine/network/drivers/host/).
TUN, NAT und die bestehende Host-Firewall liegen daher im Host-Netzwerknamespace.
Es werden keine Docker-Portweiterleitungen angelegt. Der Container bekommt
`/dev/net/tun`, eine nicht privilegierte UID, eine nur lesbare Root-Dateisystemansicht,
`cap_drop: ALL` und `no-new-privileges`. Ein kurzer Root-Helfer bereitet das
persistente, dieser UID gehörende TUN auf dem Host vor.

## Zertifikate und Konfiguration

Auf einem vertrauenswürdigen Rechner ein neues, privates Verzeichnis erzeugen:

```sh
python3 tools/keygen.py /privater/pfad/loki-pki
```

Die CA und die privaten Schlüssel gehören weder ins Repository noch in ein
Image. Nur `ca.pem`, `server.pem` und `server.key` in ein separates Verzeichnis
auf dem Server übertragen. Der Laptop erhält `ca.pem`, `client.pem` und
`client.key`. `ca.key` separat und offline aufbewahren.

Beispiel für Daemon-UID/GID 1000:

```sh
sudo install -d -m 0700 -o 1000 -g 1000 /etc/loki/server-keys
sudo install -m 0600 -o 1000 -g 1000 /sicherer/transfer/ca.pem /etc/loki/server-keys/
sudo install -m 0600 -o 1000 -g 1000 /sicherer/transfer/server.pem /etc/loki/server-keys/
sudo install -m 0600 -o 1000 -g 1000 /sicherer/transfer/server.key /etc/loki/server-keys/
cp .env.example .env
chmod 600 .env
```

In `.env` insbesondere `LOKI_WAN_IFACE`, `LOKI_KEYS_DIR`, `LOKI_UID` und
`LOKI_GID` anpassen. Die Benutzer-ID muss größer als null sein. Die Dateien
müssen dieser UID gehören und `0600` haben; ihr Verzeichnis muss für sie
zugänglich sein. Es darf nur die drei Server-Dateien enthalten. Bei SELinux
ist zusätzlich eine passende lokale Freigabe für den lesenden Containerzugriff
nötig; die Konfiguration schaltet SELinux nicht aus.

| Einstellung | Vorgabe / Bedeutung |
| --- | --- |
| `LOKI_WAN_IFACE` | tatsächliches Internet-Interface, z. B. `ens3` |
| `LOKI_KEYS_DIR` | absolutes privates Server-Verzeichnis |
| `LOKI_UID` / `LOKI_GID` | `1000:1000`, Besitzer von TUN und Schlüsseln |
| `LOKI_PORT` | UDP `4433` |
| `LOKI_TUN` | `cvpn0` |
| `LOKI_MTU` | innere MTU `1280`, gültig `1280..9000` |
| `LOKI_BIND_ADDRESS` | `0.0.0.0` |
| `LOKI_PEER_NAME` | erwarteter Client-SAN `client.cvpn` |
| `LOKI_IMAGE` | lokales Image `loki-vpn:local` |

Die Tunneladressen sind mit dem Host-Helfer fest `10.203.0.1/30` für den
Server und `10.203.0.2/30` für den Client. `LOKI_LOCAL_IP`/`LOKI_PEER_IP`
existieren nur für isolierte Container-Tests; der Host-Helfer weist abweichende
Adressen zurück.

`.env` enthält Einstellungen, keine Passwörter oder privaten Schlüssel.
[Compose übernimmt die Variablenauflösung](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/);
der Python-Helfer liest dessen aufgelöste JSON-Konfiguration. Er führt `.env`
nicht als Shellcode aus. Shell-Umgebungsvariablen können Compose-Werte ebenfalls
überschreiben; für reproduzierbaren Betrieb die Werte in `.env` setzen und
unerwünschte `LOKI_*`-Exporte entfernen.

## Start, Logs und Stop

```sh
sudo python3 tools/compose.py up
sudo python3 tools/compose.py status
sudo python3 tools/compose.py logs
```

Der Start baut zuerst das Image samt C-Protokolltest und bereitet danach die
Host-Schnittstelle vor. Ein passender vorhandener Server-Zustand kann
wiederverwendet werden. Ein abweichender Zustand wird abgewiesen. Einen alten
nativen Serverprozess vorher kontrolliert beenden; zwei Daemons können nicht
gleichzeitig dasselbe TUN und denselben UDP-Port verwenden.

Die eigene nftables-Konfiguration erlaubt nur den Tunnel-Client beim Forwarding
und richtet NAT ein. Eine vorhandene Host- oder Cloud-Firewall muss zusätzlich
UDP zum konfigurierten Port und den Rückverkehr sowie Forwarding vom TUN zum
WAN erlauben. ICMP-Nachrichten für PMTU dürfen nicht blockiert werden. Die
eigenen Accept-Regeln überschreiben keine Drop-Regeln anderer Firewallketten.

Bei einem bereits gebauten Image:

```sh
sudo python3 tools/compose.py up --no-build
```

Ein laufender Container allein bedeutet noch keinen authentifizierten Tunnel.
Erst `Tunnel ready.` nach der Zertifikats- und HELLO-Prüfung bestätigt die
Sitzung. Dafür muss der passende Laptop-Client laufen.

```sh
sudo python3 tools/compose.py down
```

Dieser Befehl stoppt den Container und nimmt anschließend die eigene
Host-Netzwerkkonfiguration zurück. `docker compose down` allein entfernt
nur den Container; TUN und eigene NAT-/Firewalltabellen bleiben dann bestehen.
Bei einem fehlgeschlagenen Setup kann `sudo python3 tools/compose.py network-down`
den dokumentierten Zwischenstand entfernen, sobald kein Daemon das TUN mehr hält.

## Image erstellen und übertragen

```sh
sudo python3 tools/compose.py build
sudo docker image save -o loki-vpn-image.tar loki-vpn:local
# Auf dem Zielserver nach sicherer Übertragung:
sudo docker image load -i loki-vpn-image.tar
sudo python3 tools/compose.py up --no-build
```

Der mehrstufige Build enthält im Laufzeit-Image den C-Daemon und OpenSSL-Laufzeitbibliotheken.
Compiler und Tests bleiben in der Build-Stufe. Die `.dockerignore` lässt nur
Build-Dateien, C-Quellen, Header, Unit-Test und Lizenz in den Build-Kontext.
Private Schlüssel werden ausschließlich beim Start als Verzeichnis eingebunden.

## Neustart des Hosts

`restart: unless-stopped` behandelt Containerneustarts. Nach einem vollständigen
Host-Neustart muss auch das TUN erneut angelegt werden, weil `/run` und das
Interface flüchtig sind. Dafür liegt eine optionale systemd-Unit bereit.

Für deren unveränderte Vorlage muss eine vollständige Kopie des Projekts
unter `/opt/loki` liegen, einschließlich `.env`, `tools/cvpn_network` und
`compose.yaml`. Die Kopie und alle übergeordneten Verzeichnisse müssen Root
gehören und für andere Benutzer nicht schreibbar sein, da systemd den
Netzwerkhelfer als Root ausführt. Die separat gespeicherten Schlüssel gehören
weiterhin der Daemon-UID. Dann:

```sh
sudo install -m 0644 /opt/loki/deploy/systemd/loki-network.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now loki-network.service
```

Die Unit bereitet das Host-Netz nach `network-online.target` und vor dem
Dockerdienst vor. `docker compose config` braucht dafür keinen laufenden
Docker-Daemon. Bei einem anderen Projektpfad die drei Pfade der Unit anpassen.
Für ein vollständiges Abschalten erst den Compose-Container stoppen, dann die
Unit deaktivieren und anschließend den Host-Zustand mit dem Helfer entfernen.

## Container-Test

Auf einem Linux-Dockerhost, nach Build des nativen Programms und des Images:

```sh
make all test
sudo python3 tests/integration/container.py --uid 1000 --gid 1000
```

Der Test erstellt eigene kurzlebige Zertifikate, zwei TUNs und ein separates
Compose-Projekt auf UDP-Port 14433. Er prüft gegenseitige Authentifizierung,
TUN-Zugriff ohne Capabilities, UID, schreibgeschützte Rootfs und `NoNewPrivs`.
Er verändert keine bestehenden VPN-Routen oder Firewalltabellen. Das Testnetz
`10.254.253.0/30` und der Testport müssen frei sein. Paketweiterleitung, NAT und
PMTU werden separat im vollständigen Namespace-Test geprüft.

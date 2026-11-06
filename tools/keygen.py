#!/usr/bin/env python3
"""Create a private CA and separate, role-restricted VPN certificates."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess


def openssl(*arguments):
    result = subprocess.run(["openssl", *map(str, arguments)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())


def generate(destination):
    os.umask(0o077)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-sha256", "-days", "3650", "-config", "/dev/null",
            "-subj", "/CN=CVPN Private CA", "-keyout", destination / "ca.key",
            "-out", destination / "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    for name, purpose in (("server", "serverAuth"), ("client", "clientAuth")):
        request = destination / f"{name}.csr"
        extensions = destination / f"{name}.ext"
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-noenc", "-sha256", "-config", "/dev/null", "-subj", f"/CN={name}.cvpn",
                "-keyout", destination / f"{name}.key", "-out", request)
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={purpose}\n"
            f"subjectAltName=DNS:{name}.cvpn\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n", encoding="ascii")
        openssl("x509", "-req", "-in", request, "-CA", destination / "ca.pem",
                "-CAkey", destination / "ca.key", "-set_serial", str(secrets.randbits(127) + 1),
                "-days", "365", "-sha256", "-extfile", extensions,
                "-out", destination / f"{name}.pem")
        request.unlink()
        extensions.unlink()
    print(f"Created credentials in {destination}")
    print("Server: ca.pem, server.pem, server.key")
    print("Laptop: ca.pem, client.pem, client.key")
    print("Keep ca.key offline; it is not needed by either running daemon.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="A new directory; existing directories are refused")
    generate(parser.parse_args().directory)

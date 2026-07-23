#!/usr/bin/env python3

from __future__ import annotations

import selectors
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform


REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "target" / "debug" / "gvm-mock-server"


@dataclass
class RunningServer:
    process: subprocess.Popen[str]
    port: int
    certificate_path: Path


@dataclass
class ClientMaterial:
    ca_path: Path
    certificate_path: Path
    key_path: Path


def build_binary() -> None:
    subprocess.run(
        ["cargo", "build", "-p", "gvm-mock-server", "--features", "tls"],
        cwd=REPO_ROOT,
        check=True,
    )


def write_client_material(directory: Path) -> ClientMaterial:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rust-gvm test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "python-gvm integration client")]
    )
    client_certificate = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / "client-ca.pem"
    certificate_path = directory / "client.pem"
    key_path = directory / "client-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(
        client_certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ClientMaterial(ca_path, certificate_path, key_path)


def read_tls_port(process: subprocess.Popen[str]) -> int:
    if process.stdout is None:
        raise RuntimeError("mock server stdout is unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 10
    output: list[str] = []
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    "mock server exited before reporting its TLS address: "
                    + "".join(output)
                )
            events = selector.select(deadline - time.monotonic())
            if not events:
                continue
            line = process.stdout.readline()
            if not line:
                continue
            output.append(line)
            prefix = "Listening on TLS: "
            if line.startswith(prefix):
                return int(line.removeprefix(prefix).strip().rsplit(":", 1)[1])
    finally:
        selector.close()

    raise TimeoutError("mock server did not report its TLS address")


def start_server(
    directory: Path,
    name: str,
    client_ca_path: Path | None = None,
) -> RunningServer:
    certificate_path = directory / f"{name}-server.pem"
    command = [
        str(BINARY),
        "--mode",
        "stateful",
        "--version",
        "22.5",
        "--tls",
        "127.0.0.1:0",
        "--tls-cert-out",
        str(certificate_path),
    ]
    if client_ca_path is not None:
        command.extend(["--tls-client-ca", str(client_ca_path)])

    process = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        port = read_tls_port(process)
        if not certificate_path.is_file():
            raise RuntimeError("mock server did not write its public certificate")
        return RunningServer(process, port, certificate_path)
    except Exception:
        stop_server(process)
        raise


def stop_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    if process.returncode not in (0, -signal.SIGINT):
        sys.stderr.write(stdout)
        sys.stderr.write(stderr)


def verify_reconnect_flow(connection: TLSConnection) -> None:
    transform = EtreeCheckCommandTransform()
    with GMP(connection=connection, transform=transform) as gmp:
        version = gmp.get_version().findtext("version")
        if version != "22.5":
            raise AssertionError(f"expected GMP 22.5, got {version!r}")

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(username="admin", password="admin")
        if gmp.get_tasks().tag != "get_tasks_response":
            raise AssertionError("authenticated GMP command did not return a task response")


def verify_anonymous_client_rejected(server: RunningServer) -> None:
    connection = TLSConnection(hostname="127.0.0.1", port=server.port)
    try:
        with GMP(
            connection=connection,
            transform=EtreeCheckCommandTransform(),
        ) as gmp:
            gmp.get_version()
    except (ConnectionError, OSError):
        return
    raise AssertionError("mTLS listener accepted an anonymous TLS client")


def main() -> int:
    build_binary()

    with tempfile.TemporaryDirectory(prefix="gvm-mock-server-tls-") as temp_dir:
        directory = Path(temp_dir)

        anonymous_server = start_server(directory, "anonymous")
        try:
            verify_reconnect_flow(
                TLSConnection(hostname="127.0.0.1", port=anonymous_server.port)
            )
            print("PASS python-gvm anonymous TLS reconnect/auth/command flow")
        finally:
            stop_server(anonymous_server.process)

        material = write_client_material(directory)
        mutual_tls_server = start_server(directory, "mtls", material.ca_path)
        try:
            verify_anonymous_client_rejected(mutual_tls_server)
            print("PASS mTLS rejects an anonymous python-gvm client")

            verify_reconnect_flow(
                TLSConnection(
                    hostname="127.0.0.1",
                    port=mutual_tls_server.port,
                    certfile=str(material.certificate_path),
                    cafile=str(mutual_tls_server.certificate_path),
                    keyfile=str(material.key_path),
                )
            )
            print("PASS python-gvm mutual TLS reconnect/auth/command flow")
        finally:
            stop_server(mutual_tls_server.process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

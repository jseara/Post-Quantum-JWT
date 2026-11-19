"""Make the TLS stack's self-signed certificate and experiment key, describe it, and trust it.

S3-04 repeats Sprint 2's sweeps over HTTPS and HTTP/2, so nginx needs a certificate for
127.0.0.1 and localhost. generate_certificate writes a new one into a run directory for every
TLS stack: certificate.pem, a self-signed X.509 v3 certificate with an EC P-256 key and an
ECDSA-SHA256 signature, valid for a few days, and experiment-key.pem, its private key, an
unencrypted PKCS#8 file created with mode 0600. The key is an ephemeral experiment key, not a
production credential: start_tls_stack deletes it when the stack stops, and it is never logged,
printed, or saved with the results. certificate_details describes a certificate without its PEM
text, as sweep.json and protocols.json record it, and client_context gives http.client an SSL
context that trusts that certificate alone and offers only HTTP/1.1 by ALPN.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CERTIFICATE_FILE = "certificate.pem"
KEY_FILE = "experiment-key.pem"
COMMON_NAME = "localhost"
ORGANIZATION = "CIS 628 transport experiment key - not a production credential"
DNS_NAMES = ("localhost",)
IP_ADDRESSES = ("127.0.0.1",)
# A few days covers any run; the not-before margin covers a clock read a moment earlier.
VALIDITY = timedelta(days=7)
CLOCK_MARGIN = timedelta(minutes=1)
# http.client speaks HTTP/1.1 only, so it offers nothing else by ALPN, even to an h2 listener.
ALPN_PROTOCOLS = ("http/1.1",)
CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    """Write an unencrypted PKCS#8 PEM key that is never readable by group or others.

    The file is created with mode 0600 by open() itself, not chmod-ed afterwards, so there is
    no moment at which another user could read it. An older file is removed first.
    """
    path.unlink(missing_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        os.fchmod(file.fileno(), 0o600)  # A umask may have narrowed it; owner-only either way.
        file.write(pem)


def generate_certificate(directory) -> tuple[Path, Path]:
    """Write a new self-signed certificate and experiment key into directory.

    Creates the directory (parents included) and returns the absolute paths of
    certificate.pem and experiment-key.pem. Every call makes a new key. The certificate is
    for DNS:localhost and IP:127.0.0.1, with basicConstraints CA:FALSE, keyUsage
    digitalSignature, extendedKeyUsage serverAuth, and subject and authority key identifiers,
    the extensions Python's strict X.509 verification expects.
    """
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    public_key = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION)])
    now = datetime.now(timezone.utc)
    alt_names = [*(x509.DNSName(dns) for dns in DNS_NAMES),
                 *(x509.IPAddress(ipaddress.ip_address(ip)) for ip in IP_ADDRESSES)]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_MARGIN)
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path, key_path = directory / CERTIFICATE_FILE, directory / KEY_FILE
    write_private_key(key_path, key)
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path, key_path


def load_certificate(certificate) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(certificate).read_bytes())


def alt_name_strings(certificate: x509.Certificate) -> list[str]:
    """The subjectAltName entries as DNS:<name> and IP:<address>, in the certificate's order."""
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    labels = {x509.DNSName: "DNS", x509.IPAddress: "IP"}
    return [f"{labels.get(type(name), type(name).__name__)}:{name.value}" for name in names]


def public_key_name(certificate: x509.Certificate) -> str:
    """The key type and size, such as 'EC P-256'."""
    key = certificate.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {CURVE_NAMES.get(key.curve.name, key.curve.name)}"
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    return type(key).__name__


def certificate_details(certificate) -> dict:
    """Describe a PEM certificate file without its PEM text, as the results record it.

    The SHA-256 fingerprint of the DER certificate is 32 uppercase hex byte pairs joined by
    ':', so it never forms a long token-like run in the results.
    """
    loaded = load_certificate(certificate)
    fingerprint = loaded.fingerprint(hashes.SHA256())
    return {
        "subject": loaded.subject.rfc4514_string(),
        "issuer": loaded.issuer.rfc4514_string(),
        "subject_alt_names": alt_name_strings(loaded),
        "not_before": loaded.not_valid_before_utc.isoformat(),
        "not_after": loaded.not_valid_after_utc.isoformat(),
        "public_key": public_key_name(loaded),
        "sha256_fingerprint": ":".join(f"{byte:02X}" for byte in fingerprint),
    }


def client_context(certificate) -> ssl.SSLContext:
    """An http.client context that verifies the server against this certificate alone.

    Certificate and host name checks stay on (CERT_REQUIRED, check_hostname), no system CA is
    loaded, and ALPN offers only http/1.1, so a TLS stack's nginx answers in HTTP/1.1 even
    when it also accepts HTTP/2.
    """
    # With a cafile, create_default_context loads only that file, not the system CAs.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(certificate))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.set_alpn_protocols(list(ALPN_PROTOCOLS))
    return context

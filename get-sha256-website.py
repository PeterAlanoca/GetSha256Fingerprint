import ssl
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def get_sha256_fingerprint(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=True)  # Obtener el certificado en formato binario

    from cryptography import x509
    cert = x509.load_der_x509_certificate(cert)

    public_key = cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key)
    sha256_hash = digest.finalize()

    import base64
    sha256_base64 = base64.b64encode(sha256_hash).decode('utf-8')

    return f"sha256/{sha256_base64}"

hostname = "website.com"
pin = get_sha256_fingerprint(hostname)
print(f"The SHA-256 pin for {hostname} is: {pin}")
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64

def get_sha256_fingerprint_from_crt(crt_path):
    with open(crt_path, "rb") as crt_file:
        crt_data = crt_file.read()

    cert = x509.load_pem_x509_certificate(crt_data)

    public_key = cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key)
    sha256_hash = digest.finalize()

    sha256_base64 = base64.b64encode(sha256_hash).decode('utf-8')

    return f"sha256/{sha256_base64}"

crt_path = "certificate.crt"
pin = get_sha256_fingerprint_from_crt(crt_path)
print(f"The SHA-256 pin of the certificate is: {pin}")
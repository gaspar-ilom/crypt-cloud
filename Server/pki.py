from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime

PRIVATE_KEY_PASS = bytes ("SecurePassphrase", 'utf-8')
issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"crypt-cloud"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"crypt-cloud"),
    ])

def loadPrivateKey():
    #only create private key if not stored in file on disk!
    try:
        f = open("privateKey.pem", "rb")
        data = f.read()
        f.close()
        return serialization.load_pem_private_key(data, PRIVATE_KEY_PASS, default_backend())
    except FileNotFoundError:
        # Generate our key on first use
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
            )
        # Write our key to disk for safe keeping -> should be stored securely in production
        with open("privateKey.pem", "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASS),
            ))
        #Create CA.pem certificate t be copied to clients!
        cert = x509.CertificateBuilder().subject_name(
            issuer
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
        # Our certificate will be valid for 10 years
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256(), default_backend())
        # Write our certificate out to disk.
        with open("CA.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return key

privateKey = loadPrivateKey()

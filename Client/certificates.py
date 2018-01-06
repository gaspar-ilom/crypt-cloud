from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY_PASS = bytes ("MySecurePassphrase", 'utf-8')

# Generate/load our private key
def loadPrivateKey():
    #only create private key if not stored in file on disk!
    try:
        f = open("myPrivateKey.pem", "rb")
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
        with open("myPrivateKey.pem", "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASS),
            ))
        return key

# Generate a CSR, write it to file and return it
def createCSR(username, privateKey):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide details about who we are: just username. Email could be added
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.USER_ID, username),
    ])).sign(privateKey, hashes.SHA512(), default_backend())
    csr = csr.public_bytes(serialization.Encoding.PEM)
    # Write our CSR out to disk.
    with open("csr.pem", "wb") as f:
        f.write(csr)
    return csr


if __name__ == '__main__':
    createCSR("admin", loadPrivateKey())

import mysql.connector
from passlib.hash import pbkdf2_sha512
#pbkdf2_sha512.verify(passwordAsBytes, hashAsString) returns True if matches!

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime

PRIVATE_KEY_PASS = bytes ("SecurePassphrase", 'utf-8')
DB_NAME = 'flaskserver'
DB_USER = 'flask-server'
DB_PASSWORD = 'test123'
DB_HOST = 'localhost'
TABLES = {}

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
        return key

privateKey = loadPrivateKey()

TABLES['user'] = (
    "CREATE TABLE IF NOT EXISTS `user` ("
    "  `username` varchar(20) NOT NULL,"
    "  `email` varchar(30) NOT NULL,"
    "  `password` varchar(255) NOT NULL,"
    "  PRIMARY KEY (`username`)"
    ") ENGINE=InnoDB")

TABLES['certificates'] = (
    "CREATE TABLE IF NOT EXISTS `certificates` ("
    "  `cert_id` varchar(64) NOT NULL,"
    "  `username` varchar(20) NOT NULL,"
    "  `cert_data` blob NOT NULL,"
    "  PRIMARY KEY (`cert_id`),"
    "  CONSTRAINT `cert_uname` FOREIGN KEY (`username`) "
    "     REFERENCES `user` (`username`) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES['revocations'] = (
    "CREATE TABLE IF NOT EXISTS `revocations` ("
    "  `username` varchar(20) NOT NULL,"
    "  `cert_id` varchar(30) NOT NULL,"
    "  PRIMARY KEY (`username`, `cert_id`),"
    "  CONSTRAINT `rev_uname` FOREIGN KEY (`username`) "
    "     REFERENCES `user` (`username`) ON DELETE CASCADE,"
    "  CONSTRAINT `rev_cert_id` FOREIGN KEY (`cert_id`) "
    "     REFERENCES `certificates` (`cert_id`) ON DELETE CASCADE"
    ") ENGINE=InnoDB")



def createTables():
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cur.execute(TABLES['user'])
    cur.execute(TABLES['certificates'])
    cur.execute(TABLES['revocations'])
    cnx.close()
    return "Success"

def createUser(username, email, password):
    stmt = ("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    pw_hash = pbkdf2_sha512.hash(password)
    try:
        cur.execute(stmt, (username, email, pw_hash))
    except mysql.connector.errors.IntegrityError as e:
        return str(e)
    cnx.commit()
    cnx.close()
    return "Success"

def retrieveCert():
    return ""

def revokeCert(u_id, cert_serial):
    return False

#create cert from csr and return it in pem-encoding and return its serial number
def createCert(csr):
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Berlin"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Berlin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"crypt-cloud"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"crypt-cloud"),
        ])
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        issuer
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
    # Our certificate will be valid for 2 years
        datetime.datetime.utcnow() + datetime.timedelta(days=(2*365))
    ).sign(privateKey, hashes.SHA512(), default_backend())

    return cert.public_bytes(serialization.Encoding.PEM), cert.serial_number

# store signed cert in DB and return it in pem-encoding,
# return None if invalid csr (i.e. hash or username does not match)
# input is required to be a username-string and csr in pem-encoding
def updateCert(username, csr):
    csr = x509.load_pem_x509_csr(csr, default_backend())
    if not csr.is_signature_valid or not username == csr.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value:
        return None
    cert, cert_id = createCert(csr)

    stmt = ("INSERT INTO certificates (cert_id, username, cert_data) VALUES (%s, %s, %s)")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    try:
        cur.execute(stmt, (cert_id, username, cert))
    except mysql.connector.errors.IntegrityError as e:
        print(e)
        return None
    cnx.commit()
    cnx.close()
    return cert

if __name__ == '__main__':
    createTables()
    createUser('admin', 'test@mail.com', 'password')
    data = None
    with open("csr.pem", "rb") as f:
        data = f.read()
    updateCert("admin", data)

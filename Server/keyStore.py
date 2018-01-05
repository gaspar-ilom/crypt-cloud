import mysql.connector
from passlib.hash import pbkdf2_sha512
#pbkdf2_sha512.verify(passwordAsBytes, hashAsString) returns True if matches!

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

backend = default_backend()

#only create cert if not stored in file/database!

# Generate our key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=backend
    )
# Write our key to disk for safe keeping
with open("privateKey.pem", "wb") as f:
    f.write(key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASS),
    ))


PRIVATE_KEY_PASS = bytes ("SecurePassphrase", 'utf-8')
DB_NAME = 'flaskserver'
DB_USER = 'flask-server'
DB_PASSWORD = 'test123'
DB_HOST = 'localhost'
CERT_COUNTER = 0
TABLES = {}

TABLES['user'] = (
    "CREATE TABLE IF NOT EXISTS `user` ("
    "  `username` varchar(20) NOT NULL,"
    "  `email` varchar(30) NOT NULL,"
    "  `password` varchar(255) NOT NULL,"
    "  PRIMARY KEY (`username`)"
    ") ENGINE=InnoDB")

TABLES['certificates'] = (
    "CREATE TABLE IF NOT EXISTS `certificates` ("
    "  `cert_id` varchar(30) NOT NULL,"
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

def updateCert(username, csr):
    stmt = ("INSERT INTO certificates (cert_id, username, cert_data) VALUES (%s, %s, %s)")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cert = ""
    try:
        cur.execute(stmt, (cert_id, username, cert))
    except mysql.connector.errors.IntegrityError as e:
        return None
    CERT_COUNTER += 1
    cnx.commit()
    cnx.close()
    return cert

if __name__ == '__main__':
    createTables()
    createUser('admin', 'test@mail.com', 'password')

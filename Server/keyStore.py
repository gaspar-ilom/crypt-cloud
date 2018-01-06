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
issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"crypt-cloud"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"crypt-cloud"),
    ])
CRL_UPDATE = datetime.datetime.utcnow().date()
REVOCATION_LIST = None

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
    "  `revoked` bool NOT NULL,"
    "  `expiry` date NOT NULL,"
    "  PRIMARY KEY (`cert_id`),"
    "  CONSTRAINT `cert_uname` FOREIGN KEY (`username`) "
    "     REFERENCES `user` (`username`) ON DELETE CASCADE"
    ") ENGINE=InnoDB")

TABLES['revocations'] = (
    "CREATE TABLE IF NOT EXISTS `revocations` ("
    "  `username` varchar(20) NOT NULL,"
    "  `cert_id` varchar(64) NOT NULL,"
    "  `revocation_date` date NOT NULL,"
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

def userExists(username):
    result = False
    stmt = ("SELECT COUNT(*) FROM user WHERE username=%s")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cur.execute(stmt, [username])
    if cur.fetchone()[0] == 1:
        result = True
    cnx.close()
    return result

# returns the users longest valid certificate
# or None if it does not exist or the user does not exist
def retrieveCert(username):
    cert = None
    if not userExists(username):
        return cert

    stmt = ("SELECT cert_data, expiry FROM certificates WHERE username=%s AND revoked=0 AND expiry>=%s ORDER BY expiry DESC")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cur.execute(stmt, [username, str(datetime.datetime.utcnow().date())])
    try:
        cert = cur.fetchone()[0]
    except TypeError:
        cnx.close()
        return cert
    cnx.close()
    return cert

# returns true if certificate is valid
def isValid(username, cert_id):
    result = False
    stmt = ("SELECT COUNT(*) FROM revocations WHERE username=%s AND cert_id=%s")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cur.execute(stmt, [username, cert_id])
    if cur.fetchone()[0] == 0:
        result = True
    cnx.close()
    return result

def revokeCert(username, cert_id=None):
    if cert_id and not isValid(username, cert_id):
        return False
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    if cert_id:
        # just revoke this specified certificate
        stmt = ("UPDATE certificates SET revoked=true WHERE username=%s AND cert_id=%s")
        cur.execute(stmt, [username, cert_id])
        stmt = ("INSERT INTO revocations (username, cert_id, revocation_date) VALUES (%s, %s, %s)")
        cur.execute(stmt, [username, cert_id, str(datetime.datetime.utcnow().date())])
    else:
        # revoke all of the users certificates if none particular specified!
        stmt = ("SELECT cert_id FROM certificates WHERE username=%s AND revoked=false")

        cur.execute(stmt, [username])
        cert_ids = cur.fetchall()
        stmt = ("UPDATE certificates SET revoked=true WHERE username=%s")
        cur.execute(stmt, [username])
        for row in cert_ids:
            stmt = ("INSERT INTO revocations (username, cert_id, revocation_date) VALUES (%s, %s, %s)")
            cur.execute(stmt, [username, row[0], str(datetime.datetime.utcnow().date())])
    cnx.commit()
    cnx.close()
    return True

#create cert from csr and return it in pem-encoding and return its serial number and validity date
def createCert(csr):
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

    return cert.public_bytes(serialization.Encoding.PEM), cert.serial_number, str(cert.not_valid_after)

# store signed cert in DB and return it in pem-encoding,
# return None if invalid csr (i.e. hash or username does not match)
# input is required to be a username-string and csr in pem-encoding
# users can update certs even though, they still have valid certs.
def updateCert(username, csr):
    csr = x509.load_pem_x509_csr(csr, default_backend())
    if not csr.is_signature_valid or not username == csr.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value:
        return None
    cert, cert_id, expiry = createCert(csr)

    stmt = ("INSERT INTO certificates (cert_id, username, cert_data, revoked, expiry) VALUES (%s, %s, %s, false, %s)")
    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    try:
        cur.execute(stmt, (cert_id, username, cert, expiry))
    except mysql.connector.errors.IntegrityError as e:
        print(e)
        return None
    cnx.commit()
    cnx.close()
    return cert

# returns the list of revoked certificates or None if no revcations so far
def getRevocationList():
    # no new update needed for now
    global CRL_UPDATE
    global REVOCATION_LIST
    if CRL_UPDATE > datetime.datetime.utcnow().date():
        return REVOCATION_LIST

    cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    cur = cnx.cursor()
    cur.execute("SELECT * FROM revocations")
    revoked = cur.fetchall()
    cnx.close()
    if len(revoked) == 0:
        # no revoked certificates
        print("here")
        return None

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))
    for cert in revoked:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            int(cert[1])
        ).revocation_date(
            datetime.datetime.strptime(str(cert[2]), '%Y-%m-%d')
        ).build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)
    REVOCATION_LIST = builder.sign(
        private_key=privateKey, algorithm=hashes.SHA512(),
        backend=default_backend()
    ).public_bytes(serialization.Encoding.PEM)
    CRL_UPDATE = datetime.datetime.utcnow().date() + datetime.timedelta(1)
    return REVOCATION_LIST

if __name__ == '__main__':
    createTables()
    createUser('admin', 'test@mail.com', 'password')
    data = None
    with open("csr.pem", "rb") as f:
        data = f.read()
    updateCert("admin", data)
    retrieveCert('admin')
    revokeCert('admin')
    #print(isValid('admin', '538079311616132818443223405735271466966159773728'))
    print(getRevocationList())

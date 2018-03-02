#!/usr/bin/env python

# Original code is from Shane Tully's "MITM Protection via the Socialist Millionaire Protocol (OTR-style)"
# https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/

#CHANGES
#modified for use in python3,
#changed hashlibrary used,
#changed randomness source to a secure os-provided source,
#modified for using a secret consisting of 2 public keys and a shared secret,
#i.e. secret = h(P_a + P_b + s), where h() is a cryptographic hashfunction and '+' denominates concatenation

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from connection import CONN
import os, struct, binascii, datetime, time, base64
import easygui as gui

class SMP(object):

    def __init__(self, initiator_certificate, replier_certificate, shared_secret):
        #modulus and generator are hardcoded
        self.mod = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
        self.modOrder = (self.mod-1) // 2
        self.gen = 2
        self.match = False
        if type(shared_secret) is str:
            # Encode the string as a hex value
            shared_secret = int(binascii.hexlify(bytes(shared_secret, 'utf-8')), 16)
        elif not type(shared_secret) is int:
            raise TypeError("Secret must be an int or a string. Got type: " + str(type(shared_secret)))
        self.secret = sha256(initiator_certificate.fingerprint(hashes.SHA256())+replier_certificate.fingerprint(hashes.SHA256())+longToBytes(shared_secret))

    def step1(self):
        self.x2 = createRandomExponent()
        self.x3 = createRandomExponent()

        self.g2 = pow(self.gen, self.x2, self.mod)
        self.g3 = pow(self.gen, self.x3, self.mod)

        (c1, d1) = self.createLogProof('1', self.x2)
        (c2, d2) = self.createLogProof('2', self.x3)

        # Send g2a, g3a, c1, d1, c2, d2
        return packList(self.g2, self.g3, c1, d1, c2, d2)

    def step2(self, buffer):
        (g2a, g3a, c1, d1, c2, d2) = unpackList(buffer)

        if not self.isValidArgument(g2a) or not self.isValidArgument(g3a):
            raise ValueError("Invalid g2a/g3a values")

        if not self.checkLogProof('1', g2a, c1, d1):
            raise ValueError("Proof 1 check failed")

        if not self.checkLogProof('2', g3a, c2, d2):
            raise ValueError("Proof 2 check failed")

        self.g2a = g2a
        self.g3a = g3a

        self.x2 = createRandomExponent()
        self.x3 = createRandomExponent()

        r = createRandomExponent()

        self.g2 = pow(self.gen, self.x2, self.mod)
        self.g3 = pow(self.gen, self.x3, self.mod)

        (c3, d3) = self.createLogProof('3', self.x2)
        (c4, d4) = self.createLogProof('4', self.x3)

        self.gb2 = pow(self.g2a, self.x2, self.mod)
        self.gb3 = pow(self.g3a, self.x3, self.mod)

        self.pb = pow(self.gb3, r, self.mod)

        self.qb = mulm(pow(self.gen, r, self.mod), pow(self.gb2, self.secret, self.mod), self.mod)

        (c5, d5, d6) = self.createCoordsProof('5', self.gb2, self.gb3, r)

        # Sends g2b, g3b, pb, qb, all the c's and d's
        return packList(self.g2, self.g3, self.pb, self.qb, c3, d3, c4, d4, c5, d5, d6)

    def step3(self, buffer):
        (g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6) = unpackList(buffer)

        if not self.isValidArgument(g2b) or not self.isValidArgument(g3b) or \
           not self.isValidArgument(pb) or not self.isValidArgument(qb):
            raise ValueError("Invalid g2b/g3b/pb/qb values")

        if not self.checkLogProof('3', g2b, c3, d3):
            raise ValueError("Proof 3 check failed")

        if not self.checkLogProof('4', g3b, c4, d4):
            raise ValueError("Proof 4 check failed")

        self.g2b = g2b
        self.g3b = g3b

        self.ga2 = pow(self.g2b, self.x2, self.mod)
        self.ga3 = pow(self.g3b, self.x3, self.mod)

        if not self.checkCoordsProof('5', c5, d5, d6, self.ga2, self.ga3, pb, qb):
            raise ValueError("Proof 5 check failed")

        s = createRandomExponent()

        self.qb = qb
        self.pb = pb
        self.pa = pow(self.ga3, s, self.mod)
        self.qa = mulm(pow(self.gen, s, self.mod), pow(self.ga2, self.secret, self.mod), self.mod)

        (c6, d7, d8) = self.createCoordsProof('6', self.ga2, self.ga3, s)

        inv = self.invm(qb)
        self.ra = pow(mulm(self.qa, inv, self.mod), self.x3, self.mod)

        (c7, d9) = self.createEqualLogsProof('7', self.qa, inv, self.x3)

        # Sends pa, qa, ra, c6, d7, d8, c7, d9
        return packList(self.pa, self.qa, self.ra, c6, d7, d8, c7, d9)

    def step4(self, buffer):
        (pa, qa, ra, c6, d7, d8, c7, d9) = unpackList(buffer)

        if not self.isValidArgument(pa):
            print ("Ppa = {}\n".format( pa ))
            raise ValueError("Invalid pa values")

        if not self.isValidArgument(qa):
            print ("Pqa = {}\n".format( qa ))
            raise ValueError("Invalid qa values")

        if not self.isValidArgument(ra):
            print ("Pra = {}\n".format( ra ))
            raise ValueError("Invalid ra values")

        if not self.checkCoordsProof('6', c6, d7, d8, self.gb2, self.gb3, pa, qa):
            raise ValueError("Proof 6 check failed")

        if not self.checkEqualLogs('7', c7, d9, self.g3a, mulm(qa, self.invm(self.qb), self.mod), ra):
            raise ValueError("Proof 7 check failed")

        inv = self.invm(self.qb)
        rb = pow(mulm(qa, inv, self.mod), self.x3, self.mod)

        (c8, d10) = self.createEqualLogsProof('8', qa, inv, self.x3)

        rab = pow(ra, self.x3, self.mod)

        inv = self.invm(self.pb)
        if rab == mulm(pa, inv, self.mod):
            self.match = True

        # Send rb, c8, d10
        return packList(rb, c8, d10)

    def step5(self, buffer):
        (rb, c8, d10) = unpackList(buffer)

        if not self.isValidArgument(rb):
            raise ValueError("Invalid rb values")

        if not self.checkEqualLogs('8', c8, d10, self.g3b, mulm(self.qa, self.invm(self.qb), self.mod), rb):
            raise ValueError("Proof 8 check failed")

        rab = pow(rb, self.x3, self.mod)

        inv = self.invm(self.pb)
        if rab == mulm(self.pa, inv, self.mod):
            self.match = True

    def createLogProof(self, version, x):
        randExponent = createRandomExponent()

        c = sha256(version + str(pow(self.gen, randExponent, self.mod)))

        d = (randExponent - mulm(x, c, self.modOrder)) % self.modOrder
        return (c, d)

    def checkLogProof(self, version, g, c, d):
        gd = pow(self.gen, d, self.mod)
        gc = pow(g, c, self.mod)
        gdgc = gd * gc % self.mod
        return (sha256(version + str(gdgc)) == c)

    def createCoordsProof(self, version, g2, g3, r):
        r1 = createRandomExponent()
        r2 = createRandomExponent()

        tmp1 = pow(g3, r1, self.mod)
        tmp2 = mulm(pow(self.gen, r1, self.mod), pow(g2, r2, self.mod), self.mod)

        c = sha256(version + str(tmp1) + str(tmp2))

        # TODO: make a subm function
        d1 = (r1 - mulm(r, c, self.modOrder)) % self.modOrder
        d2 = (r2 - mulm(self.secret, c, self.modOrder)) % self.modOrder

        return (c, d1, d2)

    def checkCoordsProof(self, version, c, d1, d2, g2, g3, p, q):
        tmp1 = mulm(pow(g3, d1, self.mod), pow(p, c, self.mod), self.mod)

        tmp2 = mulm(mulm(pow(self.gen, d1, self.mod), pow(g2, d2, self.mod), self.mod), pow(q, c, self.mod), self.mod)

        cprime = sha256(version + str(tmp1) + str(tmp2))

        return (c == cprime)

    def createEqualLogsProof(self, version, qa, qb, x):
        r = createRandomExponent()
        tmp1 = pow(self.gen, r, self.mod)
        qab = mulm(qa, qb, self.mod)
        tmp2 = pow(qab, r, self.mod)

        c = sha256(version + str(tmp1) + str(tmp2))
        tmp1 = mulm(x, c, self.modOrder)
        d = (r - tmp1) % self.modOrder

        return (c, d)

    def checkEqualLogs(self, version, c, d, g3, qab, r):
        tmp1 = mulm(pow(self.gen, d, self.mod), pow(g3, c, self.mod), self.mod)
        tmp2 = mulm(pow(qab, d, self.mod), pow(r, c, self.mod), self.mod)

        cprime = sha256(version + str(tmp1) + str(tmp2))
        return (c == cprime)

    def invm(self, x):
        return pow(x, self.mod-2, self.mod)

    def isValidArgument(self, val):
        return (val >= 2 and val <= self.mod-2)

def packList(*items):
    buffer = b''

    # For each item in the list, convert it to a byte string and add its length as a prefix
    for item in items:
        bytes = longToBytes(item)
        buffer += struct.pack('!I', len(bytes)) + bytes
    return buffer

def unpackList(buffer):
    items = []

    count = 0

    index = 0
    while index < len(buffer):
        # Get the length of the long (4 byte int before the actual long)
        length = struct.unpack('!I', buffer[index:index+4])[0]
        index += 4

        if length == 0:
            break

        # Convert the data back to a long and add it to the list
        item = bytesToLong(buffer[index:index+length])
        items.append(item)
        index += length
        count += 1

    return items

def bytesToLong(bytes):
    length = len(bytes)
    string = 0
    for i in range(length):
        string += byteToLong(bytes[i:i+1]) << 8*(length-i-1)
    return string

def longToBytes(long):
    bytes = b''
    while long != 0:
        bytes = longToByte(long & 0xff) + bytes
        long >>= 8
    return bytes

def padBytes( bytes, pad_len ):
    while ( len( bytes ) < pad_len ):
        bytes = longToByte( 0 ) + bytes
    return bytes

def byteToLong(byte):
    return struct.unpack('B', byte)[0]

def longToByte(long):
    return struct.pack('B', long)

def mulm(x, y, mod):
    return x * y % mod

def createRandomExponent():
    return int(binascii.hexlify(os.urandom(192)),16)

def sha256(message):
    if type(message) is str:
        message = bytes(message,'utf-8')
    elif not type(message) is bytes:
        raise TypeError("Hash message must be a string or bytes string. Got type: " + str(type(message)))
    hasher = hashes.Hash(hashes.SHA256(), default_backend())
    hasher.update(message)
    return int(binascii.hexlify(hasher.finalize()), 16)


class SMP_verifier(object):
    shared_secret = None
    question = None
    steps = ['question','step1', 'step2','step3','step4']
    step = 0
    smp = None
    initiated = False

    def __init__(self, initiator_certificate, replier_certificate, initiator=True):
        self.initiator_certificate = initiator_certificate
        self.replier_certificate = replier_certificate
        self.resource = "/smp/{}_{}/".format(
        initiator_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        replier_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        self.initiator = initiator
        self.start_time = datetime.datetime.utcnow()
        if initiator:
            self.initiate()
        else:
            self.reply()

    def initiate(self):
        self.clear()
        self.question, self.shared_secret = gui.multenterbox("Provide a question only your counterpart knows the answer of:",'SMP: Question and Shared Secret', ['Question', 'Shared Secret'])
        resp = CONN.post(self.resource+self.steps[self.step], data={"question": self.question})
        if not resp.status_code == 200:
            gui.msgbox("SMP verification initiation was not successful.\n{}".format(resp.json()), 'ERROR')
            return
        self.step +=1
        self.smp = SMP(self.initiator_certificate, self.replier_certificate, self.shared_secret)
        self.initiated = True

    def reply(self):
        #request Question
        resp = CONN.get(self.resource+self.steps[self.step])
        if not resp.status_code == 200:
            gui.msgbox("SMP verification reply was not successful.\n{}".format(resp.json()), 'ERROR')
            self = None
            return
        self.question = resp.json()['question']
        #self.display()
        #provide answer
        self.shared_secret = gui.enterbox("Provide the answer to the following question, i.e. the secret you share with your counterpart:\n{}".format(self.question),'Shared Secret')
        self.step += 1
        self.smp = SMP(self.initiator_certificate, self.replier_certificate, self.shared_secret)
        self.initiated = True

    def verify(self):
        if not self.initiated:
            self.clear()
            return False
        if self.initiator:
            # Do the SMP protocol
            buffer = self.receive()
            while not buffer:
                time.sleep(0.1)
                buffer = self.receive()
                if not self.time_check():
                    return False
            buffer = self.smp.step2(buffer)
            self.send(buffer)
            buffer = self.receive()
            while not buffer:
                time.sleep(0.1)
                buffer = self.receive()
                if not self.time_check():
                    return False
            buffer = self.smp.step4(buffer)
            self.send(buffer)
        else:
            # Do the SMP protocol
            buffer = self.smp.step1()
            #print ("buffer = {}\n".format(  buffer ))
            self.send(buffer)
            buffer = self.receive()
            while not buffer:
                time.sleep(0.1)
                buffer = self.receive()
                if not self.time_check():
                    return False
            buffer = self.smp.step3(buffer)
            self.send(buffer)
            buffer = self.receive()
            while not buffer:
                time.sleep(0.1)
                buffer = self.receive()
                if not self.time_check():
                    return False
            self.smp.step5(buffer)
        # Check if the secrets match
        if self.smp.match:
            print("Secrets match.")
        else:
            print("Secrets do not match.")
        #Cleanup and return True only if protocol terminated within the required time limit = 5 min
        if not self.time_check():
            return False
        self.clear()
        return self.smp.match

    def send(self, buffer):
        CONN.post(self.resource+self.steps[self.step], data={'data': base64.b64encode(buffer)})
        self.step += 1

    def time_check(self):
        passed = self.start_time + datetime.timedelta(minutes=1) > datetime.datetime.utcnow()
        if passed:
            return True
        gui.msgbox("SMP took too long. Verification failed.", 'Info')
        self.clear()
        return False

    def receive(self):
        resp = CONN.get(self.resource+self.steps[self.step])
        buffer = None
        try:
            buffer = resp.json()['data']
        except KeyError:
            return None
        if buffer:
            self.step += 1
            return base64.b64decode(buffer)
        return None

    def clear(self):
        self.initiated = False
        resource = self.resource
        if self.initiator:
            resource += self.steps[0]
        else:
            resource += self.steps[1]
        CONN.delete(resource)
        self.shared_secret = None
        self.question = None

    def display(self):
        gui.msgbox("Question: {}".format(self.question), 'SMP Question')
        if self.shared_secret:
            print("Provided answer: ".format(self.shared_secret))

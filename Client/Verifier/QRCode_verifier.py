from qrcode import make
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import zbar, cv2, base64, binascii

class QRCode_verifier(object):
    combined_fingerprint = None

    def __init__(self, displayer_certificate, reader_certificate):
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        hasher.update(displayer_certificate.fingerprint(hashes.SHA256())+reader_certificate.fingerprint(hashes.SHA256()))
        self.combined_fingerprint = hasher.finalize()
        # print(self.combined_fingerprint)

    def display_qrcode(self):
        qr = make(base64.b64encode(self.combined_fingerprint))
        qr.show()

    def verify_qrcode(self):
        capture = cv2.VideoCapture(0)
        print("Send KeyboardInterrupt (Ctrl+C) to abort verification.")
        try:
            while True:
                #Unfortunately manual abortion is not possible without a working GUI, see comment below -> Use Ctrl+C (KeyboardInterrupt) instead.
                if (cv2.waitKey(1) & 0xFF) == 'q':
                    print('Aborted verification.')
                    return False
                ret, frame = capture.read()
                # Currently not possible to display the camera image frame due to a bug/incompatibility in cv2
                #cv2.imshow('Camera', frame)
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                img = Image.fromarray(gray)
                res = zbar.Scanner().scan(img)
                for decoded in res:
                    try:
                        if base64.b64decode(decoded.data) == self.combined_fingerprint:
                            print("Fingerprint succesfully verified!")
                            return True
                    except binascii.Error:
                        print("Could not read fingerprint. It is not base64 encoded. Data read from QRCode:")
                        print(decoded.data)
                        return False
                    print("Fingerprints did not match. You are using different certificates. Update the certificates retrieved from PKI at both cliens. If the problem persists, it might indicate a Man-in-the-Middle Attack.")
                    return False
        except KeyboardInterrupt:
            print('\nAborted verification.')
            return False

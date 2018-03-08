# CryptCloud
Author: [Valentin Franck] <gaspar_ilom@campus.tu-berlin.de>
This is just a Proof of Concept and should not be used in production for a number of reasons.
* The Client application contains an unaudited implementation of a cryptographic protocol (SMP) and secret keys are not stored securely in general (i.e. they are stored as a file in the application foldes instead of using the OS' keyring for example. This is particularly troublesome because the server acts as the CA in a PKI.).
* TLS is not switched on by default, but this could easily be done in both the server and the Client.

# CryptCloud Server
Most settings for the server application can be changed in the main module 'app.py'. In particular this means the Database URI, Debug-Mode (which is set to True and must be set to False in production), the Secret Key, the Password Salt and the CA's Private Key Passphrase in
'pki.py'.
The Server stores all data in a Database. By default this is a Mysql Database, named "flaskserver", user "flask-server", password "test123", run at localhost. These values can be changed in 'app.py'.
The root certificate will be created after the first request and stored as 'CA.pem' in the application directory. It should be copied to the Client (see below).

## Prerequisites:
* Python 3.5.2 (only Python version tested on Ubuntu 16.04)

* Flask (0.12.2)
* Flask-RESTful (0.3.6)
* Flask-Security (3.0.0)
* Flask-SQLAlchemy (2.3.2)
* Werkzeug (0.14.1)
* WTForms (2.1)
* cryptography (2.1.4)
* mysqlclient (1.3.12)

## Install Requirements
Note that some of the prerequisites have dependencies of their own. So it is the easiest way to use pip:
```sh
pip install cryptography flask flask_security flask_sqlalchemy flask_restful mysqlclient
```

## Launch Server application
```sh
python app.py
```

# CryptCloud Client
The client stores most of its configuration in the 'Configuration' subfolder. In 'Configuration/settings.py' the host and port of the server can be specified. By default it loads the CA's root certificate from 'Configuration/CA.pem'. (Note this certificate is created automatically, when the server is first launched and should be copied to the Client's 'Configuration'-folder.)
Once the client has registered it will store its private key, the corresponding certificate issued by the CA, its secure passphrase and its credentials in the respective files in plaintext in the 'Configuration'-folder. Yet another reason not to use this in production. Never.
The Client can recover its private key and certificate from the server. This is useful to add a new device to an existing account. (For that purpose the private key is stored encrypted with a secure twelve random word passphrase.)
The Client allows to mutually verify other users' certificates in a synchronous SMP-session (requires a weak natural language word as a shared secret) or by scanning QR-Code from another user's device (requires a physical meeting).
Data encryption is hybrid, i.e. for each file uploaded to the Server an AES-256-CBC key is generated to encrypt the data. This key is then encrypted with all users private keys, which allows easy and secure sharing!
The Client provides a rudimentary gui, and will write some logs to stdout.

## Prerequisites:
* Python 3.5.2 (only version tested on Ubuntu 16.04)
* zbar http://zbar.sourceforge.net/
* opencv https://sourceforge.net/projects/opencvlibrary/

* cryptography (2.1.4)
* easygui (0.98.1)
* beautifulsoup4 (4.6.0)
* bs4 (0.0.1)
* zbar-py (1.0.4)
* numpy (1.14.1)
* opencv-python (3.4.0.12)
* Pillow (5.0.0)
* qrcode (5.3)
* requests (2.18.4)
* urllib3 (1.22)

## Install Requirements
Note that some of the prerequisites have dependencies of their own. So it is the easiest way to use pip:
```sh
pip install cryptography easygui beautifulsoup4 bs4 zbar-py numpy opencv-python Pillow qrcode requests urllib3
```

## Launch Server application
```sh
python app.py
```

## Known Issues

* No display of camera image, when reading QR-Codes from camera: https://github.com/skvark/opencv-python/issues/46
* Unfortunately easygui does not handle threads well. So the user will only be informed of Notifications after each interaction with Main Menu. This could be changed to a shell-based interaction of by implementing a proper gui. In order to answer a SMP request refresh Notifications from time to time.

# LICENSE

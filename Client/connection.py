from http.client import HTTPConnection
import requests

SERVER_HOST = 'localhost'
SERVER_PORT = '5000'

CONN = HTTPConnection(SERVER_HOST+':'+SERVER_PORT)

HEADERS = {"Content-Type": "application/json"}

SESSION = requests.session()

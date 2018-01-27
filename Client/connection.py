from http.client import HTTPConnection

#create a connection
CONN = HTTPConnection('localhost:5000')

HEADERS = {"Content-Type": "application/json"}

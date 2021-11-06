#client

import socket
import random
import string
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Signature import PKCS1_v1_5
import hmac
import hashlib

session_id = ""
server_random = ""
client_random = ""

def socket_connect(HOST="127.0.0.1", PORT=6969):
	#create a socket and connect to the server
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
		return s


def client_hello(s):

	global server_random
	global client_random
	global session_id

	#generate random string
	version = "1.2"
	
	client_random = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
	
	cipher_suite = "TLS_DHE_RSA_WITH_DES_CBC_SHA"

	packet = version +"::"+ client_random + "::" + cipher_suite

	s.send(packet.encode())
	server_hello = s.recv(1024).decode()

	#split the server hello into the random string and the cipher suite
	server_hello = server_hello.split("::")
	server_version = server_hello[0]

	if server_version != version:
		print("Server version is not correct")
		s.close()
		return

	server_random = server_hello[1]
	server_cipher_suite = server_hello[2]
	session_id = server_hello[3]
	
	if(server_cipher_suite!=cipher_suite):
		print("Cipher suite not supported")
		return
	
	s.send("yes".encode())

def server_cert(s):

	global session_id

	#receive the server certificate
	server_certificate = s.recv(10000).decode()
	s.send("yes".encode())
	server_certificate = server_certificate.split("::")

	G = int(server_certificate[0])
	N = int(server_certificate[1])

	gx = int(server_certificate[2])

	public_key = server_certificate[3]

	
	print("Session ID: "+session_id)
	public_key = RSA.import_key(public_key)

	#recieve the signature	
	signature = s.recv(10000)

	keyVerifier = PKCS1_v1_5.new(public_key)
	hash = SHA256.new((str(G) + "::" + str(N) + "::" + str(gx)).encode())

	if (keyVerifier.verify(hash, signature)):
		pass
	else:
		print("Signature verification unsuccessful")
		return
	
	y = random.randint(0, 100)

	gy = G ** y % N

	#send the gy to the server
	s.send(str(gy).encode())

	gxy = gx ** y % N

	pre_master = str(gxy)+str(client_random)+str(server_random)

	master_secret = hmac.new(pre_master.encode(),"master_secret".encode(), hashlib.sha256)

	print("Master secret: ",master_secret.hexdigest())

	

def main():
	s = socket_connect()
	client_hello(s)
	server_cert(s)


if __name__ == "__main__":
	main()  
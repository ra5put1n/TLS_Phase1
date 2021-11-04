#server
import socket
import random
import string
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Signature import PKCS1_v1_5
import sympy
import hmac
import hashlib

client_random = ""
server_random = ""



def socket_listen(HOST="", PORT=6969):
	#create a socket and connect to the server
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((HOST, PORT))
		s.listen(5) 
		print("Listening on localhost:{}".format(PORT))
		conn, addr = s.accept()
		print("Connected to {}:{}".format(addr[0], addr[1]))
		return conn


def server_hello(conn):

	global client_random
	global server_random

	version = "1.2"
	packet = conn.recv(1024).decode()
	lst = packet.split("::")

	client_version = lst[0]

	if (client_version != version):
		print("Client version is not compatible with server version")
		conn.close()
		return
	
	client_random = lst[1]

	cipher_suite = lst[2]

	server_random = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

	packet = version+ "::"+server_random+ "::" + cipher_suite

	conn.send(packet.encode())
	conn.recv(1024).decode()
	

def server_certificate(conn):

	certificate = RSA.generate(2048)
	public_key = certificate.publickey()
	public_key_string = public_key.exportKey(format='PEM').decode()

	#generate random number
	x = random.randint(0, 100)
	G = random.randint(500, 999)
	N = sympy.randprime(500, 999)

	gx = G**x % N
	
	packet = str(G) + "::" + str(N) + "::" + str(gx)

	hash = SHA256.new(packet.encode())

	signer = PKCS1_v1_5.new(certificate)
	signature = signer.sign(hash)

	packet += "::" + str(public_key_string)

	conn.send(packet.encode())
	conn.recv(1024)
	conn.send(signature)

	gy = int(conn.recv(1024).decode())

	gxy = gy ** x % N

	pre_master = str(gxy)+str(client_random)+str(server_random)

	master_secret = hmac.new(pre_master.encode(),"master_secret".encode(), hashlib.sha256)
	
	print("\nMaster secret: ",master_secret.hexdigest())


def main():
	conn = socket_listen()
	server_hello(conn)
	server_certificate(conn)
	conn.close()

if __name__ == "__main__":
	main()
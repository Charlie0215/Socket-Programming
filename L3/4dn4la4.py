import socket
import time
import os
import argparse
import sys
import threading
from threading import Threading

class Server:
	HOSTNAME = '0.0.0.0'
	CHATROOM_DISCOVERY_PORT = 30000

	SD_SOCKET_ADDR = (HOSTNAME, CHATROOM_DISCOVERY_PORT)
	MSG_ENCODING = 'utf-8'

	RECV_SIZE = 1024

	def __init__(self):
		self.get_chatroom_discovery_socket()
		self.receive_forever()

	def get_chatroom_discovery_socket(self):
		try:
			self.SDsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.SDsocket.bind(SD_SOCKET_ADDR)
			print('Chat Room Directory Server listening on port {}'.format(PORT))
			print('-'*72)

		except Exception as msg:
			print(msg)
			sys.exit(1)

	########################################################################
	# for Connect
	########################################################################
	def listen_for_chatroom_discovery(self):
		while True:
			# Check for service discovery queries and respond with
			# server name and address
			data, address = self.SDsocket.recvfrom(Server.RECV_SIZE)
			addr, port = address
			data = data.decode('utf-8')
			if data == 'Connect':
				print('Boradcast recieved', data, address)
				self.SDsocket.sendto('Connection from {} port {}'.format(addr, port).encode(MSG_ENCODING), address)
				print('-'*72)
			else:
				pass

	def receive_forever(self):
		Thread(target=self.listen_for_chatroom_discovery).start()
		while True:
			client = self.FSsocket.accept()
			Thread(target=self.connection_handler, args=(client,).start)
	def connection_handler(self, client):
		connection, address_port = client
		connection.setblocking(True)
		threadName = threading.crrentThread().getName()
		print(threadName, ' - Connection recieved from, ', address_port)
		while True:
			cmd = connection.recv(RECV_SIZE)
			if cmd == 'getdir':
				try:
					self.getdir()
				except:
					pass
			if cmd == 'makeroom':
				try:
					self.makeroom()
				except:
					pass
			if cmd == 'deleteroom':
				try:
					self.deleteroom()
				except:
					pass


	def makeroom(self):
		pass
	def getdir(self):
		pass
	def deleteroom(self):
		pass



class Client:
	#HOSTNAME = '255.255.255.255'
	HOSTNAME = socket.gethostname()
	CHATROOM_DISCOVERY_PORT = 30000
	CHATROOM_ADDRESS = (HOSTNAME, CHATROOM_DISCOVERY_PORT)

	RECV_SIZE = 1024

	def __init__(self):
	'''
	def get_chatroom(self):
		try:
			self.SDsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self.SDsocket.settimeout(3)
		except Exception as msg:
			print(msg)
			sys.exit(1)
	'''
	def connect(self):
		try:
			self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			pass
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_console_input(self):
		while True:
			self.input_text = input('input command: ')
			if self.input_text != '':
				try:
					connect_prompt_cmd, *connect_prompt_args = self.input_text.split()
				except Exception as msg:
					print(msg)
					continue
				if connect_prompt_cmd == 'connect':
					try:
						self.connect()
					except Exception as msg:
						print(msg)
				elif connect_prompt_cmd == 'bye':
					try:
						self.bye()
					except Exception as msg:
						print(msg)
					break
				else:
					print('Please input valid command')


	def get_service_discovery_socket(self):
		pass
	########################################################################
	# for Connect
	########################################################################
	def connect(self):
		self.CRSP = CHATROOM_ADDRESS
		print('Connecting to the chatroom server ... ')
		try:
			self.socket.connect(CHATROOM_ADDRESS)
			print('Connected!')
			print('-'*72)

		except Exception as msg:
			print(msg)
		
	def name(self, chatname):
		pass
	def chat(self, roomname):
		pass
	########################################################################
	# for bye
	########################################################################
	def bye(self):
		try:
			self.CRDS_socket.close()
		except Exception as msg:
			print(msg)



if __name__ == '__main__':

parser = argparse.ArgumentParser()
parser.add_argument('-r', dest='role', type=str, required='True', help='role of machine')
arg = parser.parse_args()

roles = {'client': Client,'server': Server}
roles[arg.role]()
import socket
import time
import os
import argparse
import sys
import multiprocessing
from multiprocessing import Process
import pickle
import struct
import threading
from threading import Thread

Lock1 = threading.Lock()
Lock2 = threading.Lock()


RX_IFACE_ADDRESS = "192.168.2.126"
MULTICAST_PORT = 2000

class Server:
	HOSTNAME = '0.0.0.0'#'0.0.0.0'
	CHATROOM_DISCOVERY_PORT = 28665
	CHATROOM_DIRECTORY_PORT = 16127

	SD_SOCKET_ADDR = (HOSTNAME, CHATROOM_DISCOVERY_PORT)
	DIR_SOCKET_ADDR = (HOSTNAME, CHATROOM_DIRECTORY_PORT)
	MSG_ENCODING = 'utf-8'

	RECV_SIZE = 2048
	BACKLOG = 10

	
	CHATROOM_LIST = {}
	CHATROOM_LIST['instruction'] = 'Content followed by Num, Name, IP, Port manner'

	def __init__(self):
		self.chatroom_dict = {}
		self.get_chatroom_discovery_socket()
		self.get_chatroom_directory_socket()
		self.receive_forever()

	def get_chatroom_discovery_socket(self):
		try:
			self.Chatroom_SD_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.Chatroom_SD_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.Chatroom_SD_socket.bind(Server.SD_SOCKET_ADDR)
			print('Chat Room Discovery Server listening on port {} ... '.format(Server.CHATROOM_DISCOVERY_PORT))
			print('-'*72)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_chatroom_directory_socket(self):
		try:
			self.Chatroom_DIR_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.Chatroom_DIR_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.Chatroom_DIR_socket.bind(Server.DIR_SOCKET_ADDR)
			self.Chatroom_DIR_socket.listen(Server.BACKLOG)
			print('Chat Room Directory Server listening on port {} ... '.format(Server.CHATROOM_DIRECTORY_PORT))
			print('-'*72)
		except Exception as msg:
			print(msg)
			sys.exit(1)


	########################################################################
	# for scan
	########################################################################
	def listen_for_service_discovery(self):
		while True:
			data, address = self.Chatroom_SD_socket.recvfrom(Server.RECV_SIZE)
			data = data.decode(Server.MSG_ENCODING)
			if data == 'SERVICE DISCOVERY':
				print("Query received: ", data, address)
				self.Chatroom_SD_socket.sendto('Chatroom Directory Server on {} {}'.format(Server.HOSTNAME, Server.CHATROOM_DIRECTORY_PORT).encode(Server.MSG_ENCODING) \
					, address)
				print('-'*72)

	########################################################################
	# for Connect
	########################################################################
	def receive_forever(self):
		
		Thread(target=self.listen_for_service_discovery).start()
		while True:
			client = self.Chatroom_DIR_socket.accept()
			Thread(target=self.connection_handler, args=(client,)).start()
			print('Connected!')
			print('-'*72)

	def connection_handler(self, client):
		connection, address_port = client
		connection.setblocking(True)
		threadName = threading.currentThread().getName()
		print(threadName,' - Connection received from ',address_port)
		while True:
			received_str = connection.recv(Server.RECV_SIZE).decode(Server.MSG_ENCODING)

			if not received_str == '':
				command, *info = received_str.split('$')
				print(command)
				if command == 'makeroom':
					try:
						self.makeroom(info)
					except Exception as msg:
						print(msg)
						return
				if command == 'getdir':
					try:
						self.getdir(connection)
					except Exception as msg:
						print(msg)
						return
				if command == 'deleteroom':
					try:
						self.deleteroom(info)
					except Exception as msg:
						print(msg)
						return
			else:
				print('Close connection')
				connection.close()
				return
	########################################################################
	# for Getdir
	########################################################################	
	def getdir(self, connection):
		data = pickle.dumps(Server.CHATROOM_LIST)
		try:
			connection.sendall(data)
			print('Sending: ')
			print(Server.CHATROOM_LIST)
			print('-'*72)
		except socket.error:
			print('Closing client connection ...')
			connection.close()
			return

	########################################################################
	# for Makeroom
	########################################################################	
	def makeroom(self, address):
		roomname = address[0]
		ipaddress = address[1]
		address_port = int(address[2])
		num_of_rooms = len(Server.CHATROOM_LIST) - 1
		newroom = [num_of_rooms, address[0], address[1], address[2]]
		Server.CHATROOM_LIST[roomname] = newroom
		print(Server.CHATROOM_LIST)
		
		self.chatroom_dict[roomname] = self.add_membership(ipaddress, address_port)
		#print('dict: ', self.chatroom_dict)
		print("Done!")
		print('-'*72)
		
	def add_membership(self, MULTICAST_ADDRESS, address_port):
		try:
			mcsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			mcsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
			BIND_ADDRESS_PORT = (MULTICAST_ADDRESS, address_port)
			mcsocket.bind(('0.0.0.0', 2000))
			multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)
			print('Multicast Group: ', MULTICAST_ADDRESS)
			multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
			multicast_request = multicast_group_bytes + multicast_if_bytes
			print('Adding membership (address/ interface): ', MULTICAST_ADDRESS,'/',RX_IFACE_ADDRESS)
			mcsocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

			return mcsocket
		except Exception as msg:
			print(msg)
			sys.exit(1)

	########################################################################
	# for Deleteroom
	########################################################################
	def deleteroom(self, name):
		name = name[0]
		del Server.CHATROOM_LIST[name]
		del self.chatroom_dict[name]



####################################################################################################################################
# Client part
####################################################################################################################################
class Client:
	#HOSTNAME = '255.255.255.255'
	HOSTNAME = socket.gethostname()
	CHATROOM_DISCOVERY_PORT = 28665
	CHATROOM_SD_ADDRESS = (HOSTNAME, CHATROOM_DISCOVERY_PORT)

	MSG_ENCODING = 'utf-8'
	RECV_SIZE = 1024

	TTL = 1 # Hops
	TTL_SIZE = 1 # Bytes
	TTL_BYTE = struct.pack('B', TTL)

	def __init__(self):
		self.get_chatroom_discovery_socket()
		self.get_chatroom_directory_socket()
		self.get_console_input()

	def get_chatroom_discovery_socket(self):
		try:
			self.Chatroom_SD_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.Chatroom_SD_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.Chatroom_SD_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self.Chatroom_SD_socket.settimeout(3)
		except Exception as msg:
			print(msg)
			sys.exit(1)
	
	def get_chatroom_directory_socket(self):
		try:
			self.Chatroom_DIR_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	########################################################################
	# for scan
	########################################################################			
	def scan_server(self):
		print('SERVICE DISCOVERY scan ...')
		# Send a service scan boardcast. If a socket timeout occurs,
		# there is probably no FS server listening
		sd_cmd = 'SERVICE DISCOVERY'.encode(Client.MSG_ENCODING)
		self.Chatroom_SD_socket.sendto(sd_cmd, Client.CHATROOM_SD_ADDRESS)
		try:
			recvd_bytes, address = self.Chatroom_SD_socket.recvfrom(Client.RECV_SIZE)
			# If a FS server responds, print put the details so that
			# we can connect to its file sharing port.
			print(recvd_bytes.decode(Server.MSG_ENCODING), 'found.')
			print('-'*72)
		except socket.timeout:
			print('No service found')

	def get_console_input(self):
		while True:
			self.input_text = input('input command: ')
			if self.input_text != '':
				try:
					connect_prompt_cmd, *connect_prompt_args = self.input_text.split()
				except Exception as msg:
					print(msg)
					continue
				##########################################
				#for Scan
				##########################################
				if connect_prompt_cmd == 'scan':
					try:
						# Transmit one or more SERVICE DISCOVERY boardcast and the SDP
						self.scan_server()
					except Exception as msg:
						print('Scan error')
						print(msg)

				##########################################
				# for Connect
				##########################################
				elif connect_prompt_cmd == 'connect':
					if not connect_prompt_args:
						print('Please enter valid server address.')
						print('Please follow format: connect <IP address> <port>')
						pass
					else:
						self.connect_server(connect_prompt_args)
				##########################################
				#For getdir
				##########################################
				elif connect_prompt_cmd == 'getdir':
					try:
						self.send_getdir()
						self.get_list_receive()
					except Exception as msg:
						print(msg)

				##########################################
				#For makeroom
				##########################################
				elif connect_prompt_cmd == 'makeroom':
					if not connect_prompt_args:
						print('Please follow format: makeroom <chat room name> <address> <port>')
					else:
						try:
							self.makeroom(connect_prompt_args)
							self.send_getdir()
							self.get_list_receive()
						except Exception as msg:
							print('Makeroom error')
							print(msg)
				##########################################
				#For Deleteroom
				##########################################
				elif connect_prompt_cmd == 'deleteroom':
					if not connect_prompt_args:
						print('Please follow format: deleteroom <chat room name>')
					else:
						try:
							self.deleteroom(connect_prompt_args)
							self.send_getdir()
							self.get_list_receive()
						except Exception as msg:
							print('deleteroom error')
							print(msg)
				##########################################
				#For Bye
				##########################################
				elif connect_prompt_cmd == 'bye':
					try:
						self.bye()
					except Exception as msg:
						print(msg)
					break


				##########################################
				#For Name
				##########################################
				elif connect_prompt_cmd == 'name':
					try:
						self.name(connect_prompt_args)
					except Exception as msg:
						print(msg)

				##########################################
				#For Chat
				##########################################
				elif connect_prompt_cmd == 'chat':
					try:
						self.chat(connect_prompt_args)
					except Exception as msg:
						print(msg)

				else:
					print('Please input valid command')
	########################################################################
	# for Connect
	########################################################################
	def connect_server(self, address):
		try:

			addr = address[0]
			port = int(address[1])
		except Exception as msg:
			print(msg)
			print('Please follow format: connect <IP address> <port>')
			return

		target_address = (addr,port)
		self.Chatroom_DIR_Server_Addr = target_address
		print('Connecting to File Sharing Server ...')
		try:
			self.Chatroom_DIR_socket.connect(target_address)
			print('Connected!')
			print('Please input the following option:\n 1. getdir\n 2. makeroom\n 3. deleteroom\n 4. bye')
			print('To make room, try 239.0.0.10 2000')
			print('-'*72)

		except Exception as msg:
			print(msg)

	########################################################################
	# for Getdir
	########################################################################
	def send_getdir(self):
		get_dir_cmd = 'getdir'.encode(Client.MSG_ENCODING)
		try:
			self.Chatroom_DIR_socket.sendto(get_dir_cmd, self.Chatroom_DIR_Server_Addr)
			print('Sending getdir command ... ')
		except Exception as msg:
			print(msg)
			sys.exit(1)
	def get_list_receive(self):
		try:
			recvd_bytes = self.Chatroom_DIR_socket.recv(Client.RECV_SIZE)
			if len(recvd_bytes) == 0:
				print("Closing server connection ... ")
				self.Chatroom_DIR_socket.close()
				sys.exit(1)
			
			print("Received: ")
			self.roomname = pickle.loads(recvd_bytes)
			print(self.roomname)
			print('-'*72)

		except Exception as msg:
			print(msg)
			return
			sys.exit(1)
	########################################################################
	# for Makeroom
	########################################################################
	def makeroom(self, address):
		try:
			print(address)
			
			roomname = address[0]
			ipaddress = address[1]
			address_port = address[2]

			address_string = 'makeroom'+'$'+roomname+'$'+ipaddress+'$'+address_port

		except Exception as msg:
			print(msg)
			print('Please follow format: makeroom <chat room name> <address> <port>')
			return
		try:
			self.Chatroom_DIR_socket.sendto(address_string.encode(Client.MSG_ENCODING), \
			 self.Chatroom_DIR_Server_Addr)
			print('Sending makeroom command')
		except Exception as msg:
			print(msg)
			return
	########################################################################
	# for Deleteroom
	########################################################################
	def deleteroom(self, name):
		try:
			roomname = name[0]
			detele_msg = 'deleteroom'+ '$' + roomname
		except Exception as msg:
			print(msg)
			print('Please follow format: deleteroom <chat room name>')
			return
		try:
			self.Chatroom_DIR_socket.sendto(detele_msg.encode(Client.MSG_ENCODING), \
			 self.Chatroom_DIR_Server_Addr)
			print('Sending deleteroom command')
		except Exception as msg:
			print(msg)
			return

	########################################################################
	# for bye (end connection)
	########################################################################
	def bye(self):
		try:
			self.CRDS_socket.close()
		except Exception as msg:
			print(msg)

	########################################################################
	# for name
	########################################################################
	def name(self, name):
		self.name = name[0]
		print('Your name is: ', self.name)
		print('-'*72)

	########################################################################
	# for chat
	########################################################################
	def chat(self, roomname):
		try:
			self.send_getdir()
			self.get_list_receive()
			ipaddress = self.roomname[roomname[0]][2]
			port = self.roomname[roomname[0]][3]
			address = (ipaddress, port)
		except Exception as msg:
			print(msg)
			return

		print('press <ctrl]> to exit ')
		# Initiate a sender and a receiver
		#Thread(target=self.send_message, args=(address,)).start()
		#Thread(target=self.receive_message, args=(address,)).start()
		self.send_message(address)
		#self.receive_message(address)

	def send_message(self, address):
		self.flag = 0
		TTL = 1 
		TTL_SIZE = 1 
		TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')
		RECV_SIZE = 256

		ipaddress = address[0]
		port = int(address[1])
		socket_addr = (ipaddress, port)


		RX_IFACE_ADDRESS = '0.0.0.0'
		MULTICAST_ADDRESS = address[0]
		self.message = ''
		try:
			##################################################################
			# For Sender socket
			##################################################################
			self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL_BYTE)

			##################################################################
			# For Receiver socket
			##################################################################
			self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
			self.recv_socket.bind(('0.0.0.0', 2000))
			# Sending Multicast group request
			multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)
			print("Multicast Group: ", MULTICAST_ADDRESS)
			multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
			multicast_request = multicast_group_bytes + multicast_if_bytes
			self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

		except Exception as msg:
			print(msg)
			sys.exit(1)

		# Dedicated thread for typing message
		input_method = Thread(target=self.input_message, args=(socket_addr,))
		#input_method.daemon = True
		input_method.start()
		
		# Receive forever
		while True:
			if self.flag == 1:
				raise Exception('control ] pressed')
			try:
				data, address_port = self.recv_socket.recvfrom(Client.RECV_SIZE)
				address, port = address_port
				receive_string = data.decode('utf-8')
				name = receive_string.split(':')[0]
				if not name == self.name:
					print("Received: ", receive_string, " Address:", address, " Port: ", port)
			except Exception as msg:
				print(1)
				print(msg)
				return
		

	def input_message(self, socket_addr):
		Lock1.acquire()
		while True:
			message = input('type your message: ')
			if message == chr(29):
				try:
					self.flag = 1
					self.message = self.name + ': Exit'
					self.send_socket.sendto(self.message.encode(Client.MSG_ENCODING), socket_addr)
					sys.exit(1)
				except:
					return
				#raise Exception("the thread is not active")
			try:
				self.message = self.name + ': ' + message
				self.send_socket.sendto(self.message.encode(Client.MSG_ENCODING), socket_addr)
				print('send!')
			except:
				print('please define name')
				return
		Lock1.release()

'''
	def receive_message(self, address):
		RX_IFACE_ADDRESS = '0.0.0.0'
		MULTICAST_ADDRESS = address[0]
		chatroom_address = address[0]
		chatroom_port = address[1]
		socket_addr = (chatroom_ipaddress, chatroom_port)
		with Lock2:
			try:
				self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
				self.recv_socket.bind(socket_addr)
							
				multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)
				print("Multicast Group: ", MULTICAST_ADDRESS)
				multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
				multicast_request = multicast_group_bytes + multicast_if_bytes

				self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
			except Exception as msg:
				print(2)
				print(msg)
				sys.exit(1)

			while True:
				try:
					print('receiving...')
					data, address_port = self.recv_socket.recvfrom(Client.RECV_SIZE)
					address, port = address_port
					print("Received: ", data.decode('utf-8'), " Address:", address, " Port: ", port)
				except Exception as msg:
					print(3)
					print(msg)
					sys.exit(1)
'''

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-r', dest='role', type=str, required='True', help='role of machine')
	arg = parser.parse_args()

	roles = {'client': Client,'server': Server}
	roles[arg.role]()


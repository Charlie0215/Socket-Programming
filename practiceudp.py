import socket
import argparse
import sys
import time
import os
import threading
from threading import Thread

CMD = { 
		'LIST': 3,
		'GET' : 1,
		'PUT' : 2,
	}
# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN  = 8 # 8 byte file size field.

class Server:

	HOSTNAME = '0.0.0.0'
	SDPORT = 30000
	FSPORT = 30001

	RECV_SIZE = 256
	BACKLOG = 10

	SD_SOCKET_ADDRESS = (HOSTNAME, SDPORT)
	FS_SOCKET_ADDRESS = (HOSTNAME, FSPORT)

	MSG_ENCODING = 'utf-8'

	FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

	shared_folder = './server_shared_folder'

	def __init__(self, filename='remotefile.txt'):
		#self.shared_dir = path
		if not os.path.exists(Server.shared_folder):
			os.makedirs(Server.shared_folder)
		self.remote_filename = filename
		self.get_service_discovery_socket()
		self.get_file_sharing_socket()
		#self.process_message_forever()
		self.receive_forever()

	def get_service_discovery_socket(self):
		try:
			self.SDsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.SDsocket.bind(Server.SD_SOCKET_ADDRESS)

			print('Listening on service discovery message on port {} ...'.format(Server.SDPORT))
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_file_sharing_socket(self):
		try:
			self.FSsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.FSsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.FSsocket.bind(Server.FS_SOCKET_ADDRESS)
			self.FSsocket.listen(Server.BACKLOG)
			print('Listening on file sharing message on port {} ...'.format(Server.FSPORT))
		except Exception as msg:
			print(msg)
			sys.exit(1)


	########################################################################
	# for scan
	########################################################################
	def listen_for_service_discovery(self):
		while True:
			# Check for service discovery queries and respond with
			# your name and address.
			data, address = self.SDsocket.recvfrom(Server.RECV_SIZE)
			data = data.decode('utf-8')
			if data == "SERVICE DISCOVERY":
				print("Broadcast received: ", data, address)
				#socket.sendto(string, address)
				self.SDsocket.sendto('Dai and Wang\'s File Sharing Service on {} port {}'.format(Server.HOSTNAME, Server.FSPORT).encode(Server.MSG_ENCODING), address)
			else:
				pass

	########################################################################
	# for connect
	########################################################################
	def receive_forever(self):
		# First, create a thread that will handle incoming service
		# discoveries.
		Thread(target=self.listen_for_service_discovery).start()
		#Thread(target=self.listen_for_file_sharing).start()
		# Then loop forever, accepting incoming file sharing
		# connections. When one occurs, create a new thread for
		# handling it.
		while True:
			# Check for new file sharing clients. Pass the new client
			# off to the connection handler with a new execution
			# thread.
			client = self.FSsocket.accept()
			##print(client)
			Thread(target=self.connection_handler, args=(client,)).start()

	def connection_handler(self, client):
		connection, address_port = client
		connection.setblocking(True)
		threadName = threading.currentThread().getName()
		print(threadName,' - Connection received from ',address_port)
		while True:
			cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')
			print(cmd)
			if cmd == CMD['PUT']:
				try:
					self.put_file(connection, address_port)
				except Exception as msg:
					print('*'*30)
					print(msg)
					return

			elif cmd  == CMD['LIST']:
				try:
					self.get_list(connection, address_port)
				except Exception as msg:
					#print('No connection')
					print(msg)
					return
			elif cmd == CMD['GET']:
				self.get_file(connection, address_port)
			else:
				print('Incorrect Command.')
				return

	########################################################################
	# for rlist
	########################################################################	
	def get_list(self, connection, address_port):
		string = ''
		dirs = os.listdir(Server.shared_folder)
		if not os.listdir(Server.shared_folder):
			print('Folder Empty.')
			msg = 'Empty.'
			string_bytes = msg.encode(Server.MSG_ENCODING)
			#return
		else:
			for file in dirs:
				string += file + ' '
			string_bytes = string.encode(Server.MSG_ENCODING)
		try:
			connection.sendall(string_bytes)
			print('Sending: ', string)

		except socket.error:
			print('Closing client connection ...')
			connection.close()
			return

	########################################################################
	# for get
	########################################################################
	def get_file(self, connection, address_port):
		filename_bytes = connection.recv(Server.RECV_SIZE)
		filename = filename_bytes.decode(Server.MSG_ENCODING)
		file_path = os.path.join(Server.shared_folder, filename)
		
		try:
			file = open(file_path, 'r').read()
		except FileNotFoundError:
			print(Server.FILE_NOT_FOUND_MSG)
			connection.close()
			#break
			return

		# Encode the file contents into bytes, record its size and
		# generate the file size field used for transmission
		file_bytes = file.encode(Server.MSG_ENCODING)
		file_size_bytes = len(file_bytes)
		file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

		# Create the packet to be sent with the header field.
		pkt = file_size_field + file_bytes

		try:
			# Send the packet to the connected client.
			connection.sendall(pkt)
			print('Sending file: ', filename)
		except socket.error:
			# If the client has closed the connection, close the
			# socket on this end.
			print('Closing client connection ...')
			connection.close()
			#break
			return

	########################################################################
	# for put
	########################################################################
	def socket_recv_size(self, length):
		bytes = connection.recv(length)
		if len(bytes) < length:
			self.socket.close()
			exit()
		return(bytes)

	def put_file(self, connection, address_port):
		filename_bytes = connection.recv(Server.RECV_SIZE)
		filename = filename_bytes.decode(Server.MSG_ENCODING)
		file_path = os.path.join(Server.shared_folder, filename)
		print(filename)

		file_size_bytes = connection.recv(FILE_SIZE_FIELD_LEN)
		if len(file_size_bytes) < FILE_SIZE_FIELD_LEN:
			connection.close()
			return
		#return(bytes)
		#file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
		if len(file_size_bytes) == 0:
			connection.close()
			return

		# Make sure that you interpret in in host byte order!!!!
		file_size = int.from_bytes(file_size_bytes, byteorder='big')

		# Recieve the file itself
		recvd_bytes_total = bytearray()

		try:
			download_filename = filename
			download_filename_path = os.path.join(Server.shared_folder, download_filename)
			# Keep doing recv until the entire file is downloaded.
			while len(recvd_bytes_total) < file_size:
				recvd_bytes_total += connection.recv(Server.RECV_SIZE)
				# Create a file using the recieved filename and store the data.
				
			
			print('Recieved {} bytes. Creating file: {}'.format(len(recvd_bytes_total), download_filename))
			with open(download_filename_path, 'a') as f:
				f.write(recvd_bytes_total.decode(Server.MSG_ENCODING))
		except KeyboardInterrupt:
			print()
			exit(1)
		


####################################################################################################################################
# Client part
####################################################################################################################################

class Client:
	BROADCAST_ADDRESS = "255.255.255.255"
	BROADCAST_PORT = 30000

	SERVER_ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)
	RECV_SIZE = 1024

	shared_folder = './client_shared'

	FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

	def __init__(self, filename='remotefile.txt'):
		#self.shared_dir = path
		if not os.path.exists(Client.shared_folder):
			os.makedirs(Client.shared_folder)
		self.remote_filename = filename
		self.get_service_discovery_socket()
		self.get_file_sharing_socket()
		self.get_console_input()

	def get_service_discovery_socket(self):
		try:
			# Create an IPv4 UDP socket
			self.SDsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			# Set socket layer socket options.
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			# Set the option for boardcasting
			self.SDsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			# Set service discovery timeout.
			self.SDsocket.settimeout(3)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_file_sharing_socket(self):
		try:
			self.FSsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			#print('Listening on file sharing message on port {} ...'.format(Server.FSPORT))
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
		sd_cmd = 'SERVICE DISCOVERY'.encode(Server.MSG_ENCODING)
		self.SDsocket.sendto(sd_cmd, Client.SERVER_ADDRESS_PORT)
		try:
			recvd_bytes, address = self.SDsocket.recvfrom(Client.RECV_SIZE)
			# If a FS server responds, print put the details so that
			# we can connect to its file sharing port.
			self.SD_addr = address
			print(recvd_bytes.decode(Server.MSG_ENCODING), 'found.', address)
		except socket.timeout:
			print('No service found')

	########################################################################
	# for connect
	########################################################################
	
	def connect_server(self, address):
		#addr = address.split(':')[0]
		#port = int(address.split(':')[1])
		try:
			addr = address[0]
			port = int(address[1])
		except Exception as msg:
			print(msg)

			return
		target_address = (addr,port)
		self.FS_addr = target_address
		print('Connecting to File Sharing Server ...')

		try:
			self.FSsocket.connect(target_address)
			print('Connected!')

		except Exception as msg:
			print(msg)

	########################################################################
	# for llist
	########################################################################
	def list_local_shared_folder(self):
		dirs = os.listdir(Client.shared_folder)
		if not os.listdir(Client.shared_folder):
			print('Folder empty.')
		else:
			for file in dirs:
				print(file)


	########################################################################
	# for rlist
	########################################################################

	def get_list_send(self):
		get_list_cmd = CMD['LIST'].to_bytes(CMD_FIELD_LEN, byteorder='big')
		try:
			self.FSsocket.sendto(get_list_cmd, self.FS_addr)
			print('rlist')
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_list_receive(self):
		try:
			# Receive and print out text. The received bytes objects
			# must be decoded into string objects.
			recvd_bytes = self.FSsocket.recv(Client.RECV_SIZE)

			# recv will block if nothing is available. If we receive
			# zero bytes, the connection has been closed from the
			# other end. In that case, close the connection on this
			# end and exit.
			#print(len(recvd_bytes))
			if len(recvd_bytes) == 0:
				print("Closing server connection ... ")
				self.socket.close()
				sys.exit(1)
				
				

			print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

		except Exception as msg:
			print(msg)
			return
			sys.exit(1)

	########################################################################
	# for get
	########################################################################
	def socket_recv_size(self, length):
		bytes = self.FSsocket.recv(length)
		if len(bytes) < length:
			self.socket.close()
			exit()
		return(bytes)

	def get_download(self, filename):
		# Create the packet GET field.
		get_field = CMD['GET'].to_bytes(CMD_FIELD_LEN, byteorder='big')

		# Create the packet filename field.
		filename_field = filename.encode(Server.MSG_ENCODING)
		#print(filename)
		# Create the packet.
		pkt = get_field + filename_field

		# Send the request packet to the server
		self.FSsocket.sendall(pkt)
		
		# Read the file size field.
		file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
		if len(file_size_bytes) == 0:
			self.FSsocket.close()
			return

		# Make sure that you interpret in in host byte order!!!!
		file_size = int.from_bytes(file_size_bytes, byteorder='big')

		# Recieve the file itself
		recvd_bytes_total = bytearray()

		try:
			download_filename = input('download file as: ')
			download_filename_path = os.path.join(Client.shared_folder, download_filename)
			# Keep doing recv until the entire file is downloaded.
			while len(recvd_bytes_total) < file_size:
				recvd_bytes_total += self.FSsocket.recv(Client.RECV_SIZE)
				# Create a file using the recieved filename and store the data.
				
			
			print('Recieved {} bytes. Creating file: {}'.format(len(recvd_bytes_total), download_filename))
			with open(download_filename_path, 'a') as f:
				f.write(recvd_bytes_total.decode(Server.MSG_ENCODING))
		except KeyboardInterrupt:
			print()
			exit(1)
		

	########################################################################
	# for put
	########################################################################
	def put_upload(self, filename):

		get_field = CMD['PUT'].to_bytes(CMD_FIELD_LEN, byteorder='big')

		# Create the packet filename field.
		filename_field = filename.encode(Server.MSG_ENCODING)
		#print(filename)
		# Create the packet.
		pkt = get_field + filename_field

		# Send the request packet to the server
		self.FSsocket.sendall(pkt)
		
		file_path = os.path.join(Client.shared_folder, filename)

		try:
			file = open(file_path, 'r').read()
		except FileNotFoundError:
			print(Client.FILE_NOT_FOUND_MSG)
			self.FSsocket.close()
			#break
			return

		# Encode the file contents into bytes, record its size and
		# generate the file size field used for transmission
		file_bytes = file.encode(Server.MSG_ENCODING)
		file_size_bytes = len(file_bytes)
		file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

		# Create the packet to be sent with the header field.
		pkt = file_size_field + file_bytes

		try:
			# Send the packet to the connected client.
			self.FSsocket.sendall(pkt)
			print('Sending file: ', filename)
		except socket.error:
			# If the client has closed the connection, close the
			# socket on this end.
			print('Closing client connection ...')
			self.FSsocket.close()
			#break
			return
		



	def get_console_input(self):
		# We are connected to the FS, Prompt the user for what to do.

		while True:
			#print('When connect, please enter in \'connect <IP>:<PORT>\' manner.')
			self.input_text = input('input command: ')
			if self.input_text != '':
				try:
					# Parse the input into a command and its
					# arguments.
					#print(self.input_text.split())
					connect_prompt_cmd, *connect_prompt_args = self.input_text.split()
				except Exception as msg:
					print(msg)
					continue
				if connect_prompt_cmd == 'scan':
					# Transmit one or more SERVICE DISCOVERY boardcast and the SDP
					self.scan_server()

				elif connect_prompt_cmd == 'connect':
					# Connect to the file sharing service at <IP address><port>
					if not connect_prompt_args:
						print('Please enter valid server address.')
						pass
					else:
						self.connect_server(connect_prompt_args)

				elif connect_prompt_cmd == 'llist':
					# Get a local files listing and print it out.
					try:
						self.list_local_shared_folder()
					except Exception as msg:
						print(msg)

				elif connect_prompt_cmd == 'rlist':
					# Do a sendall and ask the FS for a remote file listing.
					# Do a recv and output the response when it returns.
					try:
						self.get_list_send()
						self.get_list_receive()
					except Exception as msg:
						print(msg)

				elif connect_prompt_cmd == 'put':
					# Write code to interact with the FS and upload a
					# file
					try:
						filename = connect_prompt_args[0]
						self.put_upload(filename)
					except Exception as msg:
						print(msg)

				elif connect_prompt_cmd == 'get':
					# Write code to interact with the FS and download
					# a file
					try:
						filename = connect_prompt_args[0]
					# filename is an array of the input filenames
						self.get_download(filename)
						self.list_local_shared_folder()
					except Exception as msg:
						print(msg)

				elif connect_prompt_cmd == 'bye':
					# Disconnect from the FS
					self.FSsocket.close()
					break

				else:
					print('Please input valid command')
					pass
				


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-r', dest='role', type=str, required=True, help='server or client')
	parser.add_argument('-p', dest='path', type=str, default='./share', help='shared folder path')
	parser.add_argument('-f', dest='filename', type=str, default='', help='required filename')
	args = parser.parse_args()

	roles = {'client': Client,'server': Server}
	roles[args.role](args.filename)





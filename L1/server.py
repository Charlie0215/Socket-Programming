#!/usr/bin/python3
import socket
import os
import numpy as np
import sys
import argparse
import getpass
import hashlib

class Server:

	# Set the server hostname used to define the server socket address
	# binding.

	HOSTNAME = '0.0.0.0'
	
	# Set the server port to bind the listen socket to
	PORT = 50000

	RECV_BUFFER_SIZE = 1024
	MAX_CONNECTION_BACKLOG = 10	

	MSG_ENCODING = 'utf-8'
	# Create server socket address. It is a tuple containing
	# addreaa/hostname and port
	SOCKET_ADDRESS = (HOSTNAME, PORT)

	SERVER_CMD = [
					'GMA',
					'GL1A',
					'GL2A',
					'GL3A', 
					'GL4A',
				]



	def __init__(self, path):
		self.path = path

		self.create_listen_socket()
		self.process_connection_forever()

	def create_listen_socket(self):
		try:
			# Create an IPV4 TCP socket
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			# Set socket layer socket options. This allows us to reuse
			# the socket without waiting for any timeouts.
			self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # check on this later

			# Bind socket to socket address, i.e., IP addtess and port.
			self.socket.bind(Server.SOCKET_ADDRESS)

			# Set socket to listen state
			self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
			print('Listening on port {} ...'.format(Server.PORT))
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def process_connection_forever(self):
		try:
			while True:
				# Block while waiting for accepting incoming
				# connections When one is accepted, pass the new
				# (cloned) socket reference to the connections handler
				# function
				self.connection_handler(self.socket.accept())
		except Exception as msg:
			print(msg)
		except KeyboardInterrupt:
			print()
		finally:
			self.socket.close()
			sys.exit(1)

	def connection_handler(self, client):
		# return value is a pair (conn, address)
		# where conn is a new socket object usable 
		# to send and receive data on the connection
		connection, address_port = client
		print('_' * 72)
		print('Connection received from {}'.format(address_port))
		grades = []
		grades.append(self.get_avg(self.path, 1)[:])
		ID, passwd, first_name, last_name, mid, lab1, lab2, lab3, lab4 = self.get_avg(self.path, 2)
		while True:
			try:
				

				# Recieve bytes over the TCP connection. This will block
				#  until "at least 1 byte or more" is available.
				recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)

				# If recv returns with zero bytes, the other end of the
				# TCP connection has closed (The other end is probably in
				# FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the 
				# server end of the connection and get the next client connection.

				if len(recvd_bytes) == 0:
					print('Closing client connection...')
					connection.close()
					break

				# Decode the received bytes back into string. Then output
				# them.
				'''
				recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
				print('Recieved:', recvd_str)
				
				if not recvd_str in Client.CLIENT_CMD and recvd_str != 'GG':
					print('Command not existed amoung GMA, GL1A, GL2A, GL3A, and GL4A')
					print('hashedID ...')
					string = recvd_str
					print(string)
				'''
				#print(type(recvd_bytes))
					
				try:
					recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
					print('Recieved:', recvd_str)
					print('avg is', grades[0][Server.SERVER_CMD.index(recvd_str)])
					string = 'avg' + str(grades[0][Server.SERVER_CMD.index(recvd_str)])
				except:
					flag = False
					index = 0
					for i in range(len(ID)):
						h = hashlib.sha256()
						h.update(ID[i].encode('utf-8'))
						h.update(passwd[i].encode('utf-8'))
						true = h.digest()
						if recvd_bytes == true:
							index = i
							print('ID, passwd, Last Name,First Name,Midterm,Lab 1,Lab 2,Lab 3,Lab 4')
							print(ID[i], passwd[i], first_name[i], last_name[i], mid[i], lab1[i], lab2[i], lab3[i], lab4[i])
							string = ID[i] + ' ' + passwd[i] + ' ' + first_name[i] + ' ' + last_name[i] + ' ' + mid[i] + ' ' + lab1[i] + ' ' + lab2[i] + ' ' + lab3[i] + ' ' + lab4[i]
							flag = True
					if flag == False:
						print('student not found')
						string = 'student not found'

				
				# Send the recieved bytes to the client
				connection.sendall(string.encode(Server.MSG_ENCODING))
				print('Sent: ', string)

			except KeyboardInterrupt:
				print()
				print('Closing client connection...')
				connection.close()
				break

	def get_avg(self, path, flag):

		mid = []
		lab1 = []
		lab2 = []
		lab3 = []
		lab4 = []

		total_mid = 0
		total_lab1 = 0
		total_lab2 = 0
		total_lab3 = 0
		total_lab4 = 0

		avg_mid = 0
		avg_lab1 = 0
		avg_lab2 = 0
		avg_lab3 = 0
		avg_lab4 = 0

		ID = []
		passwd = []
		first_name = []
		last_name = []


		with open(path, 'r') as f:
			for i, line in enumerate(f):
				if i > 0:
					line_Arr = line.split(',')

					ID.append(line_Arr[0])
					passwd.append(line_Arr[1])
					first_name.append(line_Arr[3])
					last_name.append(line_Arr[2])

					mid.append(line_Arr[4])

					total_mid += int(line_Arr[4])

					lab1.append(line_Arr[5])
					total_lab1 += int(line_Arr[5])

					lab2.append(line_Arr[6])
					total_lab2 += int(line_Arr[6])

					lab3.append(line_Arr[7])
					total_lab3 += int(line_Arr[7])

					lab4.append(line_Arr[8])
					total_lab4 += int(line_Arr[8])

		avg_mid = float(total_mid / len(mid))
		avg_lab1 = float(total_lab1 / len(lab1))
		avg_lab2 = float(total_lab2 / len(lab2))
		avg_lab3 = float(total_lab3 / len(lab3))
		avg_lab4 = float(total_lab4 / len(lab4))

		#print('midtern avg is %f', avg_mid)
		if flag == 1:
			return avg_mid, avg_lab1, avg_lab2, avg_lab3, avg_lab4
		if flag == 2:
			return ID, passwd, first_name, last_name, mid, lab1, lab2, lab3, lab4



class Client:

	# Set the server hostname to connect to. If the server and client
	# are running on the same machine, we can use the current
	# hostname.
	SERVER_HOSTNAME = socket.gethostname()
	

	RECV_BUFFER_SIZE = 1024

	CLIENT_CMD = [
					'GMA',
					'GL1A',
					'GL2A',
					'GL3A', 
					'GL4A',
				]

	def __init__(self):
		self.get_socket()
		self.connect_to_server()
		self.send_console_input_forever()
		self.grade = False 

	def get_socket(self):
		try:
			# Create an IPv4 TCP socket.
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def connect_to_server(self):
		try:
			# Connect to the server using its socket address tuple.
			self.socket.connect((Server.HOSTNAME, Server.PORT))
			print('yes')
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def get_console_input(self):
		# In this version we keep prompting the user until a non-blank
		# line is entered.
		while True:
			input_text = input("Input: ")
			
			if not input_text in Client.CLIENT_CMD and input_text != 'GG':
				print('Command not existed')
				print('GMA, GL1A, GL2A, GL3A, GL4A or GG')
				self.input_text = input_text.encode(Server.MSG_ENCODING)
				break
			if input_text == 'GG':
				m = hashlib.sha256()
				#self.grade = True
				id = getpass.getpass(prompt='Student ID')
				p = getpass.getpass(prompt='Password')
				self.input_text = id  + p

				input_byte = self.input_text.encode('utf-8')

				m.update(input_byte)
				self.input_text = m.digest()

			if input_text in Client.CLIENT_CMD:
				self.input_text = input_text.encode(Server.MSG_ENCODING)

			if input_text != "":
				break
	
	def send_console_input_forever(self):
		while True:
			try:
				self.get_console_input()
				#if self.Grade == True:
				#	self.connection_send_GG():
				#	self.connection_send()
				#	self.connection_receive()

				#else:	
				self.connection_send()
				self.connection_receive()
			except (KeyboardInterrupt, EOFError):
				print()
				print("Closing server connection ...")
				self.socket.close()
				sys.exit(1)
				
	def connection_send(self):
		try:
			# Send string objects over the connection. The string must
			# be encoded into bytes objects first.
			self.socket.sendall(self.input_text)
		except Exception as msg:
			print(msg)
			sys.exit(1)
	def connection_send_GG(self):
		try:
			# Send string objects over the connection. The string must
			# be encoded into bytes objects first.
			self.socket.sendall('GG'.encode(Server.MSG_ENCODING))
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def connection_receive(self):
		try:
			# Receive and print out text. The received bytes objects
			# must be decoded into string objects.
			recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

			# recv will block if nothing is available. If we receive
			# zero bytes, the connection has been closed from the
			# other end. In that case, close the connection on this
			# end and exit.
			if len(recvd_bytes) == 0:
				print("Closing server connection ... ")
				self.socket.close()
				sys.exit(1)

			print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

		except Exception as msg:
			print(msg)
			sys.exit(1)




if __name__ == '__main__':
	#get_avg('course_grades_2019.csv')
	#print(socket.gethostname())
	
	roles = {'client': Client,'server': Server}
	parser = argparse.ArgumentParser()
	parser.add_argument('-r', dest='role', type=str, required=True, help='server or client role')
	parser.add_argument('-p', dest='path', type=str, default='course_grades_2019.csv', help='csv dir')
	args = parser.parse_args()
	if args.role == 'server':
		Server(args.path)
	if args.role == 'client':
		Client()




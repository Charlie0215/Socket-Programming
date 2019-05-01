import socket
import argparse
import sys
import time
import struct

#from config import *



########################################################################
#
# Address configuration for MulticastSenderReceiverConfig.py
#
########################################################################

# Two sample multicast addresses to experiment with.

MULTICAST_ADDRESS = "239.0.0.10"
# MULTICAST_ADDRESS = "239.0.0.11"

# The UDP port to which we will be sending/receiving.

MULTICAST_PORT = 2000

# The multicast address and interface (address) are part of the add
# membership request that is passed to the lower layers. If you choose
# "0.0.0.0", the system will select the interface, which will probably
# work ok in most cases. In more complex situations, where, for
# example, you may have multiple network interfaces, you may have to
# specify the interface explicitly, by using its address.

RX_IFACE_ADDRESS = "0.0.0.0"
# RX_IFACE_ADDRESS = "192.168.1.22"

# The receiver socket bind address. This is used at the IP/UDP level
# to filter incoming multicast receptions. Using "0.0.0.0" should work
# ok but if for example, the same host is receiving multiple multicast
# groups on the same port, each application may receive all multicast
# group transmissions. 

RX_BIND_ADDRESS = MULTICAST_ADDRESS
# RX_BIND_ADDRESS = "0.0.0.0"

########################################################################
# Define some things used in MulticastSenderReceiverConfig.py

# Sender:
MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)

# Receiver:
BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)



class Sender:
	HOSTNAME = socket.gethostname()

	TIMEOUT = 2
	RECV_SIZE = 256

	MSG_ENCODING = 'utf-8'
	MESSAGE = HOSTNAME + ' multicast beacon: '
	MESSAGE_ENCODED = MESSAGE.encode(MSG_ENCODING)

	TTL = 1 # Hops

	# OR: TTL_BYTE = struct.pack('B', TTL)
	TTL_SIZE = 1 # Bytes
	TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

	def __init__(self):
		self.create_listen_socket()
		self.send_message_forever()

	def create_listen_socket(self):
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Sender.TTL_BYTE)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def send_message_forever(self):
		try:
			while True:
				print('Sending multicast packet (address, port): ', MULTICAST_ADDRESS_PORT)
				self.socket.sendto(Sender.MESSAGE_ENCODED, MULTICAST_ADDRESS_PORT)
				time.sleep(Sender.TIMEOUT)
		except Exception as msg:
			print(msg)
		except KeyboardInterrupt:
			print()
		finally:
			self.socket.close()
			sys.exit(1)

class Receiver:
	
	RECV_SIZE = 256
	def __init__(self):
		print('Bind address/port = ', BIND_ADDRESS_PORT)
		self.get_socket()
		self.receive_forever()

	def get_socket(self):
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

			# Bind to an address/port. In multicast, this is viewed as
			# "filter" that determines what packets make it to the
			# UDP app.
			self.socket.bind(BIND_ADDRESS_PORT)

			############################################################
			# The multicast_request must contain a bytes object
			# consisting of 8 bytes. The first 4 bytes are the
			# multicast group address. The second 4bytes are the
			# interface address to be used. An all zeros I/F address
			# means all network interfaces
			############################################################

			multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)
			print('Multicast Group: ', MULTICAST_ADDRESS)
			# Set up the interface to be used.
			multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
			# From the multicast request.
			multicast_request = multicast_group_bytes + multicast_if_bytes

			# You can use struct.pack to create the request, bbut it is more complicated, e.g.,
			# 'struct.pack('<4sl', multicast_group_bytes,
			# int.from_bytes(multicast_if_bytes, byteorder='little'))'
			# or 'struct.pack('<4sl', multicast_group_bytes, socket.INADDR_ANY)'

			# Issue the Multicast IP Add Membership request.
			print('Adding membership (address/ interface): ', MULTICAST_ADDRESS,'/',RX_IFACE_ADDRESS)
			self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def receive_forever(self):
		while True:
			try:
				data, address_port = self.socket.recvfrom(Receiver.RECV_SIZE)
				address, port = address_port
				print('Received: ', data.decode('utf-8'), ' Address: ', address, ' Port: ', port)
			except KeyboardInterrupt:
				print()
				exit()
			except Exception as msg:
				print(msg)
				sys.exit(1)
if __name__ == '__main__':
	roles = {'receiver': Receiver,'sender': Sender}
	parser = argparse.ArgumentParser()

	parser.add_argument('-r', '--role',
						choices=roles, 
						help='sender or receiver role',
						required=True, type=str)

	args = parser.parse_args()
	roles[args.role]()













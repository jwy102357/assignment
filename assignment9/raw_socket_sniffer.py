import os
import socket
import argparse
import struct

ETH_P_ALL = 0x0003
ETH_SIZE = 14

def make_ethernet_header(raw_data) :
	ether = struct.unpack('!6B6BH', raw_data)
	return {'dst' : '%02x:%02x:%02x:%02x:%02x:%02x' % ether[:6],
			'src' : '%02x:%02x:%02x:%02x:%02x:%02x' % ether[6:12],
			'ether_type':ether[12]}

def make_IP_Header(data) :
   nVersion = data[14] // 16
   headerLength = (data[14] % 16)
   nSize = headerLength * 4
   
   ipHeader = struct.unpack('!BHHHBBH4B4B', data[15:nSize + 14])
   nFlag = ipHeader[3] >> 13
   nOffset = 0x1fff  & ipHeader[3]
   
   return {'version' : nVersion,
           'header_length' : headerLength,
           'tos' : ipHeader[0],
           'total_length' : ipHeader[1],
           'id' : ipHeader[2],
           'flag' : nFlag,
           'offset' : nOffset,
           'ttl' : ipHeader[4],
           'procotol' : ipHeader[5],
           'checksum' : ipHeader[6],
           'src' : '%d.%d.%d.%d' % ipHeader[7:11],
           'dst' : '%d.%d.%d.%d' % ipHeader[11:15]}

def dumpcode(buf):
	print("%7s"% "offset ", end='')

	for i in range(0, 16):
		print("%02x " % i, end='')

		if not (i%16-7):
			print("- ", end='')

	print("")

	for i in range(0, len(buf)):
		if not i%16:
			print("0x%04x" % i, end= ' ')

		print("%02x" % buf[i], end= ' ')

		if not (i % 16 - 7):
			print("- ", end='')

		if not (i % 16 - 15):
			print(" ")

	print("")

def sniffing(nic):
	if os.name == 'nt':
		address_familiy = socket.AF_INET
		protocol_type = socket.IPPROTO_IP
	else:
		address_familiy = socket.AF_PACKET
		protocol_type = socket.ntohs(ETH_P_ALL)

	cnt = 0
	while True :
		with socket.socket(address_familiy, socket.SOCK_RAW, protocol_type) as sniffe_sock:
			sniffe_sock.bind((nic, 0))

			if os.name == 'nt':
				sniffe_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
				sniffe_sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

			data, _ = sniffe_sock.recvfrom(65535)
			ethernet_header = make_ethernet_header(data[:ETH_SIZE])

			cnt += 1
			print('[%d] IP_PACKET---------------------------------------------' %cnt)
			print('\nEthernet Header')
			for item in ethernet_header.items() :
				print('[{0}]  {1} '.format(item[0], item[1]))

			if ethernet_header['ether_type'] == 2048 :
				IP_header = make_IP_Header(data)
				print('\nIP Header')
				for item in IP_header.items() :
					print('[{0}]  {1}'.format(item[0], item[1]))

			if os.name == 'nt':
				sniffe_sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
				
			print('\nRaw Data')
			dumpcode(data)

			if os.name == 'nt':
				sniffe_sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='This is a simpe packet sniffer')
	parser.add_argument('-i', type=str, required=True, metavar='NIC name', help='NIC name')
	args = parser.parse_args()

	sniffing(args.i)

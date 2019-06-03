import os
import socket
import argparse
import struct
import sys
import time
import random

ETH_P_ALL = 0x0003
ETH_SIZE = 14

class CIPheader :
   def __init__(self, dst, src='0') :
      self.dst = dst
      self.src = src
      self.raw = None
      self.createIPHeader()

   def assemble(self) :
      self.raw = struct.pack('!BBHHHBBH4s4s', 
      self.version,
      self.tos,
      self.totalLength,
      self.id,
      self.flag,
      self.ttl,
      self.prototype,
      self.chksum,
      self.saddr,
      self.daddr)
      
      return self.raw

   def createIPHeader(self) :
      version = 4
      HeaderLength = 5
      print('dst = %s' %self.dst)
      self.version = (version << 4) + HeaderLength
      self.tos = 0
      self.totalLength = 0
      self.id = 0
      self.flag = 0
      self.ttl = 255
      self.prototype = 17
      self.chksum = 0
      self.saddr = socket.inet_aton(self.src)
      self.daddr = socket.inet_aton(self.dst)
   
   def dissemble(self) :
      oList = struct.unpack('!BBHHHBBH4B4B', self.raw)
      oDict = {}
      
      oDict['Version'] = oList[0]
      oDict['HeaderLength'] = (oList[0] % 16)
      oDict['Tos'] = oList[1]
      oDict['TotalLength'] = oList[2]
      oDict['Id'] = oList[3]
      oDict['Flag'] = oList[4] >> 13
      oDict['Offset'] = oList[4] & 0x1fff
      oDict['TTL'] = oList[5]
      oDict['Protocol'] = oList[6]
      oDict['Chksum'] = oList[7]
      oDict['src'] = socket.inet_aton(self.src)
      oDict['dst'] = socket.inet_aton(self.src)
      print(oDict['src'])
      return oDict

class CICMPheader :
   def __init__(self, size, icmpType = 8, icmpCode = 0, icmpChksum = 0, icmpId = 0, icmpSeq = 0) :
      
      self.icmpType = icmpType
      self.icmpCode = icmpCode
      self.icmpChksum = icmpChksum
      self.icmpId = random.randint(1, 65535)
      self.icmpSeq = icmpSeq
      self.data = ''
      self.raw = None
      self.size = size
      self.createICMPHeader()

   def createICMPHeader(self) :
      self.raw = struct.pack('!BBHHH', 
         self.icmpType,
         self.icmpCode,
         self.icmpChksum,
         self.icmpId,
         self.icmpSeq)
      
      self.data = makeData(self.size)
      self.icmpChksum = self.makeChksum(self.raw + self.data.encode())

      self.raw = struct.pack('!BBHHH',
         self.icmpType,
         self.icmpCode,
         self.icmpChksum,
         self.icmpId,
         self.icmpSeq)

   def makeChksum(self, data) :
      csum = 0
      countTo = (len(data) / 2) * 2
      count = 0

      while count < countTo :
         if(data[count + 1] == 32 and count == len(data) - 2) :
               thisVal = data[count]
         else :
               thisVal = data[count + 1] * 256 + data[count]
         
         csum = csum + thisVal
         csum = csum & 0xffffffff
         count = count + 2

      if countTo < len(data) :
         csum = csum + data[len(data) - 1]
         csum = csum & 0xffffffff
      
      csum = (csum >> 16) + (csum & 0xffff)
      csum = csum + (csum >> 16)
      result = ~csum
      result = result & 0xffff
      result = result >> 8 | (result << 8 & 0xff00)
      return result

class CUDPheader :
   def __init__(self, size, iph, dst, src = 0, length = 0, udpChksum = 0, data = '') :
      self.src = src
      self.dst = dst
      self.length = size - 20
      self.udpChksum = udpChksum
      self.data = data
      self.size = size
      self.iph = iph
      self.createUDPHeader()

   def createUDPHeader(self) :
    oDict = self.iph.dissemble()

    self.data = makeData(self.size)

    Pseudo = struct.pack('!4s4sBBHHHHH',
        oDict['src'],
        oDict['dst'],
        0x00,
        0x11,
        8 + len(self.data),
        self.src,
        self.dst,
        8 + len(self.data),
        self.udpChksum)

    self.udpChksum = self.makeChksum(Pseudo + self.data.encode())

    self.raw = struct.pack('!HHHH',
        self.src,
        self.dst,
        self.length,
        self.udpChksum)

   def makeChksum(self, data) :
      csum = 0
      countTo = (len(data) / 2) * 2
      count = 0

      while count < countTo :
         if(data[count + 1] == 32 and count == len(data) - 2) :
               thisVal = data[count]
         else :
               thisVal = data[count + 1] * 256 + data[count]
         
         csum = csum + thisVal
         csum = csum & 0xffffffff
         count = count + 2

      if countTo < len(data) :
         csum = csum + data[len(data) - 1]
         csum = csum & 0xffffffff
      
      csum = (csum >> 16) + (csum & 0xffff)
      csum = csum + (csum >> 16)
      result = ~csum
      result = result & 0xffff
      result = result >> 8 | (result << 8 & 0xff00)
      print("%04x" %result)
      return result

def makeData(size) :
   datalen = size - 28 if size > 28 else  1
   data = ''
   for i in range(datalen) :
      data += 'A'
   return data

def run(dst, size, c, pt, port = 0) :
   for i in range(6, c+2) :
      sender(dst, size, i, pt, port)
      receiver(dst)
      print('c = %d' %(i-1))

def sender(dst, size, c, pt, port = 0) :
   with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
      sock.connect((dst,0))

      iph = CIPheader(dst)

      if pt == 'u' :
         iph.prototype = 17
         ia = iph.assemble()
         uh = CUDPheader(size = size, iph = iph, dst = port)
         iph.ttl = c
         data = ia + uh.raw + uh.data.encode()
         sock.send(data)
      elif pt == 'i' :
         iph.prototype = 1
         ciph = CICMPheader(size = size)
         iph.ttl = c
         data = iph.assemble() + ciph.raw + ciph.data.encode()
         sock.send(data)

def receiver(dst) :
   with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:

      try :
         sock.settimeout(1)
         data = sock.recv(65535)
         dumpcode(data)
      except :
         None

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

if __name__ == '__main__':
   parser = argparse.ArgumentParser()
   parser.add_argument('host')
   parser.add_argument('size', type = int)
   parser.add_argument('-t', help = 'RECV_TIMEOUT', required = False, default = 10, type = int)
   parser.add_argument('-c', help = 'MAX_HOPS', required = False, default = 10, type = int)
   parser.add_argument('-u', required = False, action = 'store_true')
   parser.add_argument('-i', required = False, action = 'store_true')
   parser.add_argument('-p', help = 'port', required = False, default = 10050, type = int)

   args = parser.parse_args()

   try :
      _host = args.host
      _ip = socket.gethostbyname(_host)

   except socket.error as identifer :
      print("error message : "  + str(identifer))
      pass

   except :
      print('all error')
      pass

   finally :
      print('end')

   if args.u :
      run(_ip, args.size, args.c, 'u', args.p)
   elif args.i :
      run(_ip, args.size, args.c, 'i')
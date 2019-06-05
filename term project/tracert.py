import socket
import argparse
import struct
import time
import random

class CIPheader :
   def __init__(self, dst, idt = random.randint(1, 65000), src='0') :
      self.dst = dst
      self.src = src
      self.id = idt
      self.raw = None
      self.createIPHeader()
      self.raw = self.assemble()

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
      self.version = (version << 4) + HeaderLength
      self.tos = 0
      self.totalLength = 0
      self.id = self.id
      self.flag = 0
      self.ttl = 255
      self.prototype = 17
      self.chksum = 0
      self.saddr = socket.inet_aton(self.src)
      self.daddr = socket.inet_aton(self.dst)
   
   def dissemble(self) :
      oList = struct.unpack('!BBHHHBBH4B4B', self.raw)
      oDict = {}
      
      oDict['Version'] = self.version
      oDict['HeaderLength'] = 5
      oDict['Tos'] = self.tos
      oDict['TotalLength'] = self.totalLength
      oDict['Id'] = self.id
      oDict['Flag'] = self.flag
      oDict['Offset'] = oList[4] & 0x1fff
      oDict['TTL'] = self.ttl
      oDict['Protocol'] = self.prototype
      oDict['Chksum'] = self.chksum
      oDict['src'] = self.saddr
      oDict['dst'] = self.daddr
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
   def __init__(self, size, iph, dst, src = random.randint(34000, 59000), length = 0, udpChksum = 0, data = '') :
      self.size = size
      self.iph = iph
      self.src = src
      self.dst = dst
      self.length = size - 20
      self.udpChksum = udpChksum
      self.data = data
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
      return result

def makeData(size) :
   datalen = (size - 28 if size > 28 else  28)
   data = ''
   for i in range(datalen) :
      data += 'A'
   return data

def run(dst, size, t, c, pt, port = 33435) :
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
      print('traceroute to %s (%s), %d hops max, %d byte packets' %(dst, _ip, c, size))
   
   port = port
   dst = _ip
   data = None
   ds = ''
   sqnum = random.randint(1, 64)
   ridt = random.randint(1, 65000)
   for i in range(1, c+1) :
      print('%2d' %i, end = '\t')
      for j in range(0, 3) :
         idt, myaddr = sender(dst, size, ridt, sqnum, i, pt, port)
         port += 1
         sqnum += 1
         data = receiver(idt, myaddr, t, pt, port)
         if data != None :
            dt = struct.unpack('!4B', data[12:16]) # source ip address
            ds = str(str(dt[0])+'.'+str(dt[1])+'.'+str(dt[2])+'.'+str(dt[3])) # 문자열로 합침
      if ds != '' :
         print('[%s, %s]' %(socket.getfqdn(ds), ds))
         ds = ''
      else :
         print('')
      if data != None :
         if data[20] == 0 : # icmp type echo reply
            break

def sender(dst, size, ridt, sqnum, c, pt, port) :
   idt = 0
   adr = ''
   with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
      sock.connect((dst,0))
      adr = sock.getsockname()[0]
      iph = CIPheader(dst, idt = ridt, src = adr)

      if pt == 'u' :
         iph.prototype = 17
         uh = CUDPheader(size = size, iph = iph, dst = port, src = random.randint(34000, 59000))
         iph.ttl = c
         data = iph.assemble() + uh.raw + uh.data.encode()
         sock.send(data)
         idt = iph.id
      elif pt == 'i' :
         iph.prototype = 1
         icph = CICMPheader(size = size, icmpSeq = sqnum)
         iph.ttl = c
         data = iph.assemble() + icph.raw + icph.data.encode()
         sock.send(data)
         idt = icph.icmpId
   return idt, adr
      
def receiver(idt, myaddr, t, pt, port) :
   start = time.time()
   getData = False
   data = None

   with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock :
      try :
         sock.settimeout(t)
         data = sock.recv(65535)
         dt = struct.unpack('!4B', data[16:20])    # destination ip adrees
         adr = str(str(dt[0])+'.'+str(dt[1])+'.'+str(dt[2])+'.'+str(dt[3]))   # 문자열로 합침
         
         if myaddr != adr :     # destination ip adrees
            print('       *', end='\t')
            return None
         else :
            if pt == 'i' :    #icmp
               if data[20] == 11 : # icmp type ttl exceeded
                  if data[52]*256 + data[53] != idt :    # icmp id 불일치
                     print('       *', end='\t')
                     return None
               if data[20] == 0 : #icmp type echo reply
                  if data[24]*256 + data[25] != idt :    # icmp id 불일치
                     print('       *', end='\t')
                     return None
            if pt == 'u' :    # udp
               if data[20] == 11 : # icmp type ttl exceeded
                  if data[32]*256 + data[33] != idt : # ip header id 불일치
                     print('       *', end='\t')
                     return None
         
         getData = True
         print('%5.2f ms' %((time.time()-start)*1000), end = '\t')
      except :
         print('       *', end='\t')

   if getData == True :
      return data

if __name__ == '__main__':
   parser = argparse.ArgumentParser()
   parser.add_argument('host')
   parser.add_argument('size', type = int)
   parser.add_argument('-t', help = 'RECV_TIMEOUT', required = False, default = 0.5, type = float)
   parser.add_argument('-c', help = 'MAX_HOPS', required = False, default = 10, type = int)
   parser.add_argument('-u', required = False, action = 'store_true')
   parser.add_argument('-i', required = False, action = 'store_true')
   parser.add_argument('-p', help = 'port', required = False, default = 53345, type = int)

   args = parser.parse_args()

   if args.u :
      run(args.host, args.size, args.t, args.c, 'u', args.p)
   elif args.i :
      run(args.host, args.size, args.t, args.c, 'i')
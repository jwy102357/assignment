import os
import socket
import argparse
import struct
import sys

def cksum(data) :
   data1 = struct.unpack('!15H', data)
   cksum=0
   for i in range(10) :
      if(i!=5) :
         cksum += data1[i]
      print('%04x' %data1[i])
   cksum = (cksum >> 16) + (cksum & 0xffff)
   cksum += (cksum >>16)
   cksum = 0xffff - cksum
   data2 = data1[0:5] + (cksum,) + data1[5:]
   print(hex(data2[5]))
   return data1

def sender(des) :
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        sock.connect((des,0))
        data = struct.pack('!15H', 0x4500, 0x0018, 0x0c8d, 0x4000, 0x4001, 0x0000, 0xc0a8, 0xdb64, 0x0808, 0x0808, 0x0800, 0xf79b,0x0000,0x0000,0x0064)
        data2 = struct.unpack('!15H', data)
        print(sys.getsizeof(data2))
        sock.send(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', required=True)
    args = parser.parse_args()

    sender(args.d)
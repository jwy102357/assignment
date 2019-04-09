import socket
import argparse
import threading
import time

def Recvmsg(host, port, s) :
    while True :
        data = s.recv(1024)
        str1=data.decode()
        print("From %s : %s, %s " %(host, port, str1))

def run(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        t = threading.Thread(target=Recvmsg, args = (host, port, s))
        t.start()
        while True :
                line = input()
                s.sendall(line.encode())

if __name__ == '__main__':
        parser = argparse.ArgumentParser(description="Echo client -p port -i host")
        parser.add_argument('-p', help = "port_number", required = True)
        parser.add_argument('-i', help = "host_name", required=True)

        args= parser.parse_args()

        run(host=args.i, port=int(args.p))

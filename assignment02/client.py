import socket
import argparse

def run(host, port, string):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        line = string
        s.sendall(line.encode())
        resp = s.recv(1024)
        print(resp.decode())

if __name__ == '__main__':
        parser = argparse.ArgumentParser(description="Echo client -p port -i host -s string")
        parser.add_argument('-p', help = "port_number", required = True)
        parser.add_argument('-i', help = "host_name", required=True)
        parser.add_argument('-s', help = "string", required=True, nargs='+')

        args= parser.parse_args()

        str1=''
        for i in range(len(args.s)) :
                str1 += args.s[i]
                if len(args.s) > i+1 :
                        str1 += ' '

        run(host=args.i, port=int(args.p), string=str1)

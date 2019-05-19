import socket
import argparse

def run_server(port = 4000):
    host = ''
    with socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)

        conn, addr = s.accept()
        msg = conn.recv(1024)
        print(msg.decode())

        str1=msg.decode()
        str2=''
        for i in range(len(str1)-1, -1, -1) :
                str2 += str1[i]

        conn.sendall(str2.encode())
        conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args= parser.parse_args()
    run_server(port = int(args.p))

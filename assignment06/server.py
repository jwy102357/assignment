import socket
import argparse
import threading


def Recvmsg(con,addr) :
    while True :
        data = con.recv(1024)
        str1=data.decode()
        print("From %s : %s, %s " %(addr[0], addr[1], str1))

def Sendmsg(con, addr) :
    while True :
        msg = input()
        con.sendall(msg.encode())

def run_server(port = 4000):
    host = ''
    with socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)

        while True:
            conn, addr = s.accept()
            print("Connected to : %s : %s " %(addr[0], addr[1]))
            t2 = threading.Thread(target=Sendmsg, args = (conn,addr))
            t2.start()
            t = threading.Thread(target=Recvmsg, args = (conn,addr))
            t.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args= parser.parse_args()
    run_server(port = int(args.p))

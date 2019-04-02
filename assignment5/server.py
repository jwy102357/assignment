import socket
import argparse
import threading

def Create(con,addr) :
    data = con.recv(1024)
    str1=data.decode()
    str2=''
    for i in range(len(str1)-1, -1, -1) :
            str2 += str1[i]
    con.sendall(str2.encode())
    print("%s Closed" % addr[0])
    con.close()

def run_server(port = 4000):
    host = ''
    with socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)

        while True:
            conn, addr = s.accept()
            print("Connected to : %s : %s " %(addr[0], addr[1]))
            threading._start_new_thread(Create,(conn,addr,))
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args= parser.parse_args()
    run_server(port = int(args.p))

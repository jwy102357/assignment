import socket
import argparse
import os


def run_server(port = 4000, filepath = os.getcwd()):
    host = ''
    with socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)

        conn, addr = s.accept()
        msg = conn.recv(1024)
        oSendString = b"Y"
        oFileString = b''
        os.chdir(filepath)
        if os.path.exists(msg) == True :
                size = os.path.getsize(os.getcwd() + '/' + msg.decode())
                oSendString += (str(size) + ":").encode()
                
                with open(msg.decode(), 'rb') as f :
                        while True:
                                data = f.read(1024)
                                oFileString += data
                                if not data:
                                        oSendString += oFileString
                                        conn.send(oSendString)
                                        break
                                
                
                fileName = os.getcwd() + '/' + msg.decode()
                print("File Name : %s" %fileName)
                print("File Size : %d" %size)

        else :
                conn.send("N".encode())
                print("존재하지 않는 파일 입니다.")
        
        conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="-p port -d filepath")
    parser.add_argument('-p', help = "port_number", required = True)
    parser.add_argument('-d', help = "File_path", required = True, nargs='+')

    args= parser.parse_args()
    
    str1=''
    for i in range(len(args.d)) :
            str1 += args.d[i]
            if len(args.d) > i+1 :
                    str1 += ' '
        
    
    run_server(port = int(args.p), filepath = str1)

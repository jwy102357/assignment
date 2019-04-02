import socket
import argparse
import os

def run(host, port, string):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        line = string
        s.sendall(line.encode())
        
        data = s.recv(1)
        recvString = ""
        nFileSize = ""
        fLoading = 0.0

        if data.decode() == 'Y' :
                while True :
                        recvString = s.recv(1)
                        if recvString.decode() == ":" :
                                print("File Size : %d" %int(nFileSize))
                                break
                        else :
                                nFileSize += recvString.decode()


                with open(line, 'wb') as f :
                        nCount = 0
                        if int(nFileSize) > 1024 :
                                nCount = int(nFileSize) // 1024
                                fCurrentLoading = 1.0
                                for i in range(nCount + 1) :
                                        data = s.recv(1024)
                                        if not data :
                                                break
                                        f.write(data)
                                        fLoading = (((i + 1) * 1024) / int(nFileSize)) * 100
                                        if fLoading > 100 :
                                                fLoading = 100
                                        
                                        if int(fLoading) > int(fCurrentLoading) :
                                                print("현재 전송 퍼센트 : %f" %fLoading)
                                                fCurrentLoading = fLoading + 1

                                        

                        else :
                                data = s.recv(int(nFileSize))
                                f.write(data)
                                fLoading = 100
                                print("현재 전송 퍼센트 : %f" %fLoading)

                print("File Name : %s" %string)
                print("전송 성공")
                
        else :
                print("전송 실패")



if __name__ == '__main__':
        parser = argparse.ArgumentParser(description="-p port -i host -s file_name")
        parser.add_argument('-p', help = "port_number", required = True)
        parser.add_argument('-i', help = "host_name", required=True)
        parser.add_argument('-f', help = "file_name", required=True)

        args= parser.parse_args()

        run(host=args.i, port=int(args.p), string=args.f)

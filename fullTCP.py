
import socket
destAddr = "192.168.100.50"
port = 50
#to_port = input('finish scan to port > ')
#counting_open = []
#counting_close = []
#threads = []
msg = 'hello'
s = socket.socket()
result = s.connect_ex((destAddr,port))
print('working on port > '+(str(port)))
if result == 0:
        print ('open')
else:
        print (result)
        print("close")
        s.close()

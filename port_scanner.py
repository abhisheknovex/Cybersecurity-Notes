import socket 
target = input (" Enter target IP:")
ports = {21,22,80,443}
for port in ports:
    scanner = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result =scanner.connect_ex((target, port))
    
    if result == 0:
        print(f"Port {port} is OPEN")
        
    else:
        print(f"Port {port}CLOSED")
        scanner.close()
        
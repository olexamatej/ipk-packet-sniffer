import socket
import signal
import sys

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    server_socket.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1", 4567))
server_socket.listen(1)

try:
    client_socket, client_address = server_socket.accept()
    print(f"Accepted connection from {client_address}")
    while True:
        data = client_socket.recv(1024)
        print("Received data:", data.decode())
        if not data:
            break
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    server_socket.close()
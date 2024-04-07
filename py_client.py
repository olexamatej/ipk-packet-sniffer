import socket

def send_message(ip, port, message):
    # Create a client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        client_socket.sendall(message.encode())
        response = client_socket.recv(1024)
        print("Response from server:", response.decode())

    except ConnectionRefusedError:
        print("Connection refused. Make sure the server is running.")

    finally:
        client_socket.close()

ip = "127.0.0.1"
port = 4567

send_message(ip, port, "hello")
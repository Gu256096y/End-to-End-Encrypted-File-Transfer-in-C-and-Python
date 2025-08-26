#Guy Rav On

import socket
import threading
from client_requests_handling import handle_client
from file_handling import read_port_from_file

# Initialize the dictionary of registered users
registered_users = {}

# Initialize file data storage for ongoing transfers
ongoing_transfers = {}

# Start the server
def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server is listening on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, registered_users, ongoing_transfers))
        client_handler.start()

def main():
    port_num = read_port_from_file('port.info')
    start_server(port_num)

if __name__ == "__main__":
    main()


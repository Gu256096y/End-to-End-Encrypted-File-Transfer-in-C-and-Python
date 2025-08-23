#Guy Rav On 315044743

import struct
import socket
from clients_management import *
from simple_crypto_handler import decrypt_file, generate_uuid_client_id
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import base64

# Constants for message structure
CLIENT_ID_SIZE = 16
VERSION_SIZE = 1
CODE_SIZE = 2
PAYLOAD_SIZE_FIELD = 4

#handling clients as threads
def handle_client(client_socket, registered_users, ongoing_transfers):
    try:
        handle_message(client_socket, registered_users, ongoing_transfers)  # Main message handling function
    except Exception as e:
        print(f"Exception handling client: {e}")
    finally:
        client_socket.close()  # Close the socket once done

# Function to handle receiving large data
def receive_full_data(client_socket, expected_size):
    received_data = b''
    while len(received_data) < expected_size:
        packet = client_socket.recv(min(4096, expected_size - len(received_data)))
        if not packet:
            break
        received_data += packet
    return received_data


# Function to handle and parse incoming messages
def handle_message(client_socket, registered_users, ongoing_transfers):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break

            # Ensure we have at least enough bytes for the fixed part of the message
            if len(data) < CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD:
                print("Invalid message: too short")
                continue

            # Unpack the fixed part of the message (little-endian)
            client_id_bytes = data[:CLIENT_ID_SIZE]
            code = struct.unpack('<H', data[CLIENT_ID_SIZE + VERSION_SIZE:CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE])[0]
            payload_size = struct.unpack('<I', data[
                                               CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE:CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD])[0]

            # If the incoming data is larger than the received part, get the full payload
            if len(data) < CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD + payload_size:
                remaining_data = receive_full_data(client_socket,
                                                   CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD + payload_size - len(data))
                data += remaining_data

            payload_start = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_FIELD
            payload = data[payload_start:payload_start + payload_size]
            if code == 825:
                handle_request_825(payload, client_socket, registered_users)
            elif code == 826:
                handle_request_826(client_id_bytes, payload, client_socket, registered_users)
            elif code == 827:
                handle_request_827(client_id_bytes, payload, client_socket, registered_users)
            elif code == 828:
                handle_request_828(client_id_bytes, payload, client_socket, registered_users, ongoing_transfers)
            elif code == 900 or code == 902:
                handle_request_900_902(client_id_bytes, payload, client_socket, registered_users)
        except socket.error as e:
            print(f"Socket error: {e}")
            break


# Function to handle registration (code 825)
def handle_request_825(payload, client_socket, registered_users):
    username = payload.split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"Received registration request for username: '{username}'")

    if is_username_registered(username, registered_users):
        print(f"Username '{username}' is already registered.")
        send_response(client_socket, 1601, b"")
    else:
        new_client_id = generate_uuid_client_id()
        register_username(username, new_client_id, registered_users)
        print(f"Username '{username}' registered with client_id {new_client_id.hex()}.")
        send_response(client_socket, 1600, new_client_id)


# Function to handle public key exchange (code 826)
def handle_request_826(client_id_bytes, payload, client_socket, registered_users):
    username = payload[:255].split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"Received public key message for username: '{username}'")

    if username in registered_users and registered_users[username]['client_id'] == client_id_bytes:
        public_key_base64 = payload[255:].decode('utf-8')
        registered_users[username]['public_key'] = public_key_base64

        try:
            public_key = RSA.import_key(base64.b64decode(public_key_base64))
            print("Public key successfully imported.")
        except Exception as e:
            print(f"Error importing public key: {e}")
            send_response(client_socket, 1602, b"")
            return

        aes_key = get_random_bytes(32)
        print(f'Generated AES key: {aes_key.hex()}')
        registered_users[username]['aes_key'] = aes_key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key)

        combined_payload = client_id_bytes + encrypted_aes_key_base64
        send_response(client_socket, 1602, combined_payload)
    else:
        print(f"Error: Username '{username}' not found or client_id mismatch.")
        send_response(client_socket, 1607, b"")


# Function to handle regular connection (code 827)
def handle_request_827(client_id_bytes, payload, client_socket,registered_users):
    username = payload[:255].split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"Received regular connection request for username: '{username}'")

    if username in registered_users:
        if registered_users[username]['client_id'] == client_id_bytes:
            stored_public_key_base64 = registered_users[username]['public_key']
            if stored_public_key_base64:
                try:
                    stored_public_key = RSA.import_key(base64.b64decode(stored_public_key_base64))
                    print(f"Stored public key successfully imported for {username}.")
                except Exception as e:
                    print(f"Error importing stored public key: {e}")
                    send_response(client_socket, 1606, client_id_bytes)
                    return

                aes_key = get_random_bytes(32)
                registered_users[username]['aes_key'] = aes_key
                print(f"Generated AES key: {aes_key.hex()}")

                rsa_cipher = PKCS1_OAEP.new(stored_public_key)
                encrypted_aes_key = rsa_cipher.encrypt(aes_key)
                encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key)

                combined_payload = client_id_bytes + encrypted_aes_key_base64
                send_response(client_socket, 1605, combined_payload)
            else:
                print(f"No public key found for {username}.")
                send_response(client_socket, 1606, client_id_bytes)
        else:
            print(f"Client ID mismatch for username {username}.")
            send_response(client_socket, 1606, client_id_bytes)
    else:
        print(f"Username {username} not found.")
        send_response(client_socket, 1606, client_id_bytes)


# Function to handle file transfer (code 828)
def handle_request_828(client_id_bytes, payload, client_socket, registered_users, ongoing_transfers):
    if len(payload) < 267:
        print("Invalid file transfer payload, too small.")
        return

    encrypted_file_size = struct.unpack('<I', payload[:4])[0]
    original_file_size = struct.unpack('<I', payload[4:8])[0]
    current_packet = struct.unpack('<H', payload[8:10])[0]
    total_packets = struct.unpack('<H', payload[10:12])[0]
    file_name = payload[12:267].split(b'\x00', 1)[0].decode('utf-8')
    file_content = payload[267:]

    # Convert client_id_bytes to hex string for directory name
    client_id_str = ''.join(f'{byte:02x}' for byte in client_id_bytes)

    # Create a directory for the client_id if it doesn't exist
    directory_path = os.path.join('uploads', client_id_str)
    os.makedirs(directory_path, exist_ok=True)

    # Save file content in the directory
    file_path = os.path.join(directory_path, file_name)

    if file_name not in ongoing_transfers:
        ongoing_transfers[file_name] = b''

    ongoing_transfers[file_name] += file_content

    print(f"Packet {current_packet}/{total_packets} received for file: {file_name}")
    print(f"Encrypted file size: {encrypted_file_size}, Original file size: {original_file_size}")

    if current_packet == total_packets:
        with open(f"{file_path}", "wb") as f:
            f.write(ongoing_transfers[file_name])
        print(f"All packets received for {file_name}. File transfer completed.")

        # Now decrypt the file
        crc = decrypt_file(client_id_bytes, file_name, registered_users)

        # Send response with code 1603
        file_size_before_decryption = len(ongoing_transfers[file_name])  # Get the size of the received file data

        # Prepare the payload
        response_payload = (
            client_id_bytes +
            struct.pack('<I', file_size_before_decryption) +
            file_name.encode('utf-8').ljust(255, b'\x00') +
            struct.pack('<I', int(crc, 16))  # Convert CRC from hex to unsigned integer
        )

        # Send the response back to the client
        send_response(client_socket, 1603, response_payload)  # Include client_socket here
        del ongoing_transfers[file_name]  # Clear the transfer buffer once complete

# Function to handle file name request (code 900)
def handle_request_900_902(client_id_bytes, payload, client_socket, registered_users):
    # The payload should only contain the file name (255 bytes)
    file_name = payload.split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"Received file name request for file: '{file_name}'")

    # Find the username associated with the client_id
    matching_users = [user for user, details in registered_users.items() if details['client_id'] == client_id_bytes]

    if not matching_users:
        print(f"No matching user found for client_id: {client_id_bytes.hex()}")
        send_response(client_socket, 1601, b"")  # Send error response if no user found
        return

    # Prepare the response payload with the client_id
    response_payload = client_id_bytes

    # Send response with code 1604
    send_response(client_socket, 1604, response_payload)

# Function to send the response to the client
def send_response(client_socket, code, payload):
    version = 0x03
    payload_size = len(payload)

    response = struct.pack('B', version)
    response += struct.pack('<H', code)
    response += struct.pack('<I', payload_size)

    if payload_size > 0:
        response += payload

    client_socket.sendall(response)
    print(f"Sent response: Version={version}, Code={code}, Payload Size={payload_size}")
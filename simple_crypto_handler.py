#Guy Rav On

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from crc_checksum import memcrc
import uuid

def decrypt_file(client_id_bytes, file_name, registered_users):
    # Convert client_id_bytes to a hex string
    client_id_hex = client_id_bytes.hex()

    # Find the username associated with the client_id
    matching_users = [user for user, details in registered_users.items() if details['client_id'] == client_id_bytes]

    if not matching_users:
        print(f"No matching user found for client_id: {client_id_hex}")
        return  # Exit the function if no matching user is found

    username = matching_users[0]  # Get the username from the first match

    # Construct the file path
    directory = os.path.join('uploads', client_id_hex)
    encrypted_file_path = os.path.join(directory, file_name)

    # Check if the file exists
    if not os.path.exists(encrypted_file_path):
        print(f"File {encrypted_file_path} does not exist.")
        return

    # Read the encrypted file
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    # Retrieve the AES key for the client
    aes_key = registered_users[username]['aes_key']
    iv = b'\x00' * AES.block_size  # Ensure the IV is set to zero, as per your project requirements

    # Decrypt the data
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Write the decrypted data to a new file
    decrypted_file_path = os.path.join(directory, f"{file_name}")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"File {file_name} decrypted successfully and saved as {file_name}.")
    calculated_crc = hex(memcrc(decrypted_data))
    return calculated_crc

# Function to generate a UUID and return it as a 16-byte string
def generate_uuid_client_id():
    new_uuid = uuid.uuid4().hex

    return bytes.fromhex(new_uuid)

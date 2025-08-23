#Guy Rav On 315044743

# Function to check if the username is already registered
def is_username_registered(username, registered_users):
    return username in registered_users


# Function to register a username with the associated client_id
def register_username(username, client_id, registered_users):
    registered_users[username] = {
        'client_id': client_id,
        'public_key': None,
        'aes_key': None
    }
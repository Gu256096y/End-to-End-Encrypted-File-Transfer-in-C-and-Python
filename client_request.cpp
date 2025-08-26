//Guy Rav On

#include "client_request.h"
#include "RSA_keys_handling.h"
#include "file_handling.h"

//function to construct a message with the given parameters
std::vector<uint8_t> construct_message(const std::string& client_id_str, uint16_t code, const std::string& payload) {
    std::vector<uint8_t> message;

    //ensure client_id is 16 bytes
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0); //Initialize to 0s for first connection
    if (!client_id_str.empty()) {
        std::memcpy(client_id.data(), client_id_str.data(), std::min(client_id_str.size(), client_id.size()));
    }
    message.insert(message.end(), client_id.begin(), client_id.end());

    //add version (1 byte)
    message.push_back(VERSION);

    //Add code (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(code & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((code >> 8) & 0xFF)); //High byte

    //Special handling for code 825 (registration)
    if (code == 825) {
        std::vector<uint8_t> padded_payload(REGISTRATION_PAYLOAD_SIZE, 0); //Initialize with 255 bytes of 0

        //Copy the username into the payload, including the null terminator
        size_t copy_length = std::min(payload.size() + 1, REGISTRATION_PAYLOAD_SIZE);
        std::memcpy(padded_payload.data(), payload.c_str(), copy_length);

        //Add payload size (4 bytes, little-endian)
        uint32_t payload_size = static_cast<uint32_t>(padded_payload.size());
        message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
        message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
        message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
        message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

        //Add the padded payload (username + padding)
        message.insert(message.end(), padded_payload.begin(), padded_payload.end());
    }
    else {
        //For other codes, handle the payload as usual
        uint32_t payload_size = static_cast<uint32_t>(payload.size());
        message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
        message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
        message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
        message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

        //Add payload (variable size)
        message.insert(message.end(), payload.begin(), payload.end());
    }

    return message;
}

//Function to construct message with public key (code 826)
std::vector<uint8_t> construct_message_with_public_key(uint16_t code, const std::string& username, const std::string& public_key_base64) {
    std::vector<uint8_t> message;

    //Read the client_id from the me.info file
    std::ifstream me_file("me.info");
    if (!me_file.is_open()) {
        throw std::runtime_error("Error opening me.info file.");
    }

    std::string stored_username, client_id_str;
    if (!(std::getline(me_file, stored_username) && std::getline(me_file, client_id_str))) {
        throw std::runtime_error("Error reading client_id from me.info file.");
    }

    //Convert client_id_str (hex format) to bytes
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0);
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        client_id[i] = static_cast<uint8_t>(std::stoi(client_id_str.substr(2 * i, 2), nullptr, 16));
    }

    message.insert(message.end(), client_id.begin(), client_id.end());

    //Add version (1 byte)
    message.push_back(VERSION);

    //Add code (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(code & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((code >> 8) & 0xFF)); //High byte

    //Special handling for code 826: username + base64 public key
    std::vector<uint8_t> padded_username(REGISTRATION_PAYLOAD_SIZE, 0); //Initialize 255 bytes to 0
    size_t copy_length = std::min(username.size() + 1, REGISTRATION_PAYLOAD_SIZE); //username + null terminator
    std::memcpy(padded_username.data(), username.c_str(), copy_length); //Copy username and null terminator

    //Add the public key (base64 encoded) to the payload
    std::vector<uint8_t> public_key_bytes(public_key_base64.begin(), public_key_base64.end());

    //Combine the padded username and the base64-encoded public key
    std::vector<uint8_t> final_payload(padded_username.begin(), padded_username.end());
    final_payload.insert(final_payload.end(), public_key_bytes.begin(), public_key_bytes.end());

    //Add payload size (4 bytes, little-endian)
    uint32_t payload_size = static_cast<uint32_t>(final_payload.size());
    message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

    //Add the final payload (username + public key)
    message.insert(message.end(), final_payload.begin(), final_payload.end());

    return message;
}

//Function to construct the message with code 827
std::vector<uint8_t> construct_message_with_client_id(uint16_t code, const std::string& client_id_str, const std::string& username) {
    std::vector<uint8_t> message;

    //Convert client_id_str (hex format) to bytes (ensure it is 16 bytes long)
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0);
    if (client_id_str.size() == CLIENT_ID_SIZE * 2) {
        for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
            try {
                client_id[i] = static_cast<uint8_t>(std::stoi(client_id_str.substr(2 * i, 2), nullptr, 16));
            }
            catch (const std::invalid_argument& e) {
                throw std::runtime_error("Invalid client ID format: " + client_id_str);
            }
            catch (const std::out_of_range& e) {
                throw std::runtime_error("Client ID out of range: " + client_id_str);
            }

        }
    }
    else {
        throw std::runtime_error("Invalid client ID length.");
    }

    //Insert the client ID (16 bytes) into the message
    message.insert(message.end(), client_id.begin(), client_id.end());

    //Add version (1 byte)
    message.push_back(VERSION);

    //Add code (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(code & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((code >> 8) & 0xFF)); //High byte

    //Prepare the username payload with null-terminator and padding
    std::vector<uint8_t> padded_username(REGISTRATION_PAYLOAD_SIZE, 0);
    size_t copy_length = std::min(username.size() + 1, REGISTRATION_PAYLOAD_SIZE); //username + null terminator
    std::memcpy(padded_username.data(), username.c_str(), copy_length); //Copy username and null terminator

    //Add payload size (4 bytes, little-endian)
    uint32_t payload_size = static_cast<uint32_t>(padded_username.size());
    message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

    //Add the padded payload (username + padding)
    message.insert(message.end(), padded_username.begin(), padded_username.end());

    return message;
}

std::vector<uint8_t> construct_message_with_encrypted_file(const std::string& client_id_str, uint16_t code, const std::vector<uint8_t>& encrypted_data, size_t original_file_size, const std::string& file_name, uint16_t packet_number, uint16_t total_packets) {
    std::vector<uint8_t> message;

    //Convert client_id to bytes (16 bytes)
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0);
    if (client_id_str.size() == CLIENT_ID_SIZE * 2) {
        for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
            client_id[i] = static_cast<uint8_t>(std::stoi(client_id_str.substr(2 * i, 2), nullptr, 16));
        }
    }
    else {
        throw std::runtime_error("Invalid client ID length.");
    }

    //**Add client_id (16 bytes) first**
    message.insert(message.end(), client_id.begin(), client_id.end());

    //Add version (1 byte)
    message.push_back(VERSION);

    //Add code (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(code & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((code >> 8) & 0xFF)); //High byte

    //Add payload size (4 bytes, little-endian)
    uint32_t payload_size = static_cast<uint32_t>(4 + 4 + 2 + 2 + 255 + encrypted_data.size());
    message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

    //Add size of the encrypted file (4 bytes, little-endian)
    uint32_t encrypted_file_size = static_cast<uint32_t>(encrypted_data.size());
    message.push_back(static_cast<uint8_t>(encrypted_file_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((encrypted_file_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((encrypted_file_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((encrypted_file_size >> 24) & 0xFF)); //Highest byte

    //Add original file size (4 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(original_file_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((original_file_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((original_file_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((original_file_size >> 24) & 0xFF)); //Highest byte

    //Add current packet number (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(packet_number & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((packet_number >> 8) & 0xFF)); //High byte

    //Add total packets (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(total_packets & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((total_packets >> 8) & 0xFF)); //High byte

    //Add file name (255 bytes, null-terminated and padded with zeros)
    std::vector<uint8_t> file_name_bytes(file_name.begin(), file_name.end());
    if (file_name_bytes.size() < 255) {
        file_name_bytes.resize(255, 0);  //Null terminator + padding
    }
    message.insert(message.end(), file_name_bytes.begin(), file_name_bytes.end());

    //Add the encrypted file content
    message.insert(message.end(), encrypted_data.begin(), encrypted_data.end());

    return message;
}

//Function to construct message for file request (code 900)
std::vector<uint8_t> construct_message_with_file_name(uint16_t code, const std::string& file_name) {
    std::vector<uint8_t> message;

    //Read the client_id from the me.info file
    std::ifstream me_file("me.info");
    if (!me_file.is_open()) {
        throw std::runtime_error("Error opening me.info file.");
    }

    std::string stored_username, client_id_str;
    if (!(std::getline(me_file, stored_username) && std::getline(me_file, client_id_str))) {
        throw std::runtime_error("Error reading client_id from me.info file.");
    }

    //Convert client_id_str (hex format) to bytes
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0);
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        client_id[i] = static_cast<uint8_t>(std::stoi(client_id_str.substr(2 * i, 2), nullptr, 16));
    }

    message.insert(message.end(), client_id.begin(), client_id.end());

    //Add version (1 byte)
    message.push_back(VERSION);

    //Add code (2 bytes, little-endian)
    message.push_back(static_cast<uint8_t>(code & 0xFF));        //Low byte
    message.push_back(static_cast<uint8_t>((code >> 8) & 0xFF)); //High byte

    //Prepare the payload with the file name
    std::vector<uint8_t> padded_file_name(255, 0); //Initialize 255 bytes to 0
    size_t copy_length = std::min(file_name.size() + 1, static_cast<size_t>(255)); //File name + null terminator
    std::memcpy(padded_file_name.data(), file_name.c_str(), copy_length); //Copy file name and null terminator

    //Add payload size (4 bytes, little-endian)
    uint32_t payload_size = static_cast<uint32_t>(padded_file_name.size());
    message.push_back(static_cast<uint8_t>(payload_size & 0xFF));         //Lowest byte
    message.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));  //Low byte
    message.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF)); //High byte
    message.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF)); //Highest byte

    //Add the final payload (file name)
    message.insert(message.end(), padded_file_name.begin(), padded_file_name.end());

    return message;
}





//Function to receive the server's response
void receive_response_1600(boost::asio::ip::tcp::socket& socket, const std::string& username) {
    std::vector<uint8_t> buffer(7); //1 byte version + 2 bytes code + 4 bytes payload size

    try {
        //Read the fixed part of the response (7 bytes)
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(buffer));
        if (bytes_read < buffer.size()) {
            throw std::runtime_error("Error: Received incomplete response header.");
        }

        //Extract version, code, and payload size
        uint8_t version = buffer[0];
        uint16_t code = (buffer[2] << 8) | buffer[1]; //little-endian code
        uint32_t payload_size = (buffer[6] << 24) | (buffer[5] << 16) | (buffer[4] << 8) | buffer[3]; //little-endian payload size

        std::cout << "Response received from server:\n";
        std::cout << "Version: " << static_cast<int>(version) << "\n";
        std::cout << "Code: " << code << "\n";
        std::cout << "Payload Size: " << payload_size << "\n";

        //Check if it's a successful registration (code 1600)
        if (code == 1600 && payload_size == 16 && !username.empty()) {
            std::vector<uint8_t> payload_buffer(payload_size);
            bytes_read = boost::asio::read(socket, boost::asio::buffer(payload_buffer));

            if (bytes_read < payload_buffer.size()) {
                throw std::runtime_error("Error: Received incomplete payload.");
            }

            //Convert the client_id (payload) to a hexadecimal string
            std::ostringstream client_id_hex;
            for (const auto& byte : payload_buffer) {
                client_id_hex << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
            }

            std::string client_id_str = client_id_hex.str();
            std::cout << "Payload (new client_id in hex): " << client_id_str << "\n";

            //Write the username and client_id to the me.info file
            std::ofstream file("me.info");
            if (!file.is_open()) {
                throw std::runtime_error("Failed to create me.info file.");
            }
            file << username << "\n" << client_id_str << "\n";
            std::cout << "me.info file created with username and client_id.\n";
        }
        else if (code == 1601) {
            std::cout << "Username already registered. No me.info file created.\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error receiving response: " << e.what() << std::endl;
    }
}

//Function to receive the server's response for code 1602
std::vector<uint8_t> receive_response_1602(boost::asio::ip::tcp::socket& socket, const std::string& username) {
    std::vector<uint8_t> buffer(7); //1 byte version + 2 bytes code + 4 bytes payload size

    try {
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(buffer));
        if (bytes_read < buffer.size()) {
            throw std::runtime_error("Error: Received incomplete response header.");
        }

        //Extract version, code, and payload size
        uint8_t version = buffer[0];
        uint16_t code = (buffer[2] << 8) | buffer[1];
        uint32_t payload_size = (buffer[6] << 24) | (buffer[5] << 16) | (buffer[4] << 8) | buffer[3];

        if (code != 1602) {
            std::cout << "Received error code: " << code << ".\n";
            if (file_exists("me.info")) {
                std::remove("me.info");
                std::cout << "Deleted me.info.\n";
            }
            if (file_exists("priv.key")) {
                std::remove("priv.key");
                std::cout << "Deleted priv.key.\n";
            }
            throw std::runtime_error("Unexpected response code: " + std::to_string(code));
        }

        //Read the payload (client ID + encrypted AES key)
        std::vector<uint8_t> payload_buffer(payload_size);
        bytes_read = boost::asio::read(socket, boost::asio::buffer(payload_buffer));
        if (bytes_read < payload_buffer.size()) {
            throw std::runtime_error("Error: Received incomplete payload.");
        }

        //Decrypt AES key and return it
        return decrypt_aes_key_from_response(payload_buffer);
    }
    catch (const std::exception& e) {
        std::cerr << "Error receiving response: " << e.what() << std::endl;
        return {};  //Return an empty vector in case of error
    }
}

//Function to receive the server's response for code 1603
uint32_t receive_response_1603(boost::asio::ip::tcp::socket& socket, const std::string& username) {
    std::vector<uint8_t> buffer(7); //Version + Code + Payload Size

    try {
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(buffer));
        if (bytes_read < buffer.size()) {
            throw std::runtime_error("Error: Received incomplete response header.");
        }

        //Extract version, code, and payload size
        uint8_t version = buffer[0];
        uint16_t code = (buffer[2] << 8) | buffer[1];
        uint32_t payload_size = (buffer[6] << 24) | (buffer[5] << 16) | (buffer[4] << 8) | buffer[3];

        //Check if the code matches
        if (code != 1603) {
            throw std::runtime_error("Unexpected response code: " + std::to_string(code));
        }

        //Read the payload
        std::vector<uint8_t> payload_buffer(payload_size);
        bytes_read = boost::asio::read(socket, boost::asio::buffer(payload_buffer));
        if (bytes_read < payload_buffer.size()) {
            throw std::runtime_error("Error: Received incomplete payload.");
        }

        //Extract CRC (last 4 bytes of the payload)
        uint32_t received_crc = (payload_buffer[payload_size - 1] << 24) |
            (payload_buffer[payload_size - 2] << 16) |
            (payload_buffer[payload_size - 3] << 8) |
            (payload_buffer[payload_size - 4]);

        std::cout << "Received CRC: " << std::hex << received_crc << std::dec << std::endl;

        return received_crc;  //Return the CRC as uint32_t
    }
    catch (const std::exception& e) {
        std::cerr << "Error receiving response: " << e.what() << std::endl;
        return 0;  //Return 0 or some error value in case of error
    }
}

//Function to receive the server's response for code 1604
void receive_response_1604(boost::asio::ip::tcp::socket& socket) {
    std::vector<uint8_t> buffer(7); //Version + Code + Payload Size

    try {
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(buffer));
        if (bytes_read < buffer.size()) {
            throw std::runtime_error("Error: Received incomplete response header.");
        }

        //Extract version, code, and payload size
        uint8_t version = buffer[0];
        uint16_t code = (buffer[2] << 8) | buffer[1];
        uint32_t payload_size = (buffer[6] << 24) | (buffer[5] << 16) | (buffer[4] << 8) | buffer[3];

        //Check if the code matches 1604
        if (code != 1604) {
            throw std::runtime_error("Unexpected response code: " + std::to_string(code));
        }

        //Read the client ID from the response
        std::vector<uint8_t> client_id_bytes(payload_size);
        bytes_read = boost::asio::read(socket, boost::asio::buffer(client_id_bytes));
        if (bytes_read < client_id_bytes.size()) {
            throw std::runtime_error("Error: Received incomplete client ID payload.");
        }

        //Read the expected client ID from me.info
        std::ifstream me_file("me.info");
        if (!me_file.is_open()) {
            throw std::runtime_error("Error opening me.info file.");
        }

        std::string stored_username, client_id_str;
        if (!(std::getline(me_file, stored_username) && std::getline(me_file, client_id_str))) {
            throw std::runtime_error("Error reading client_id from me.info file.");
        }

        //Convert client_id_str (hex format) to bytes
        std::vector<uint8_t> expected_client_id(CLIENT_ID_SIZE, 0);
        for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
            expected_client_id[i] = static_cast<uint8_t>(std::stoi(client_id_str.substr(2 * i, 2), nullptr, 16));
        }

        //Compare received client ID with expected client ID
        if (std::equal(client_id_bytes.begin(), client_id_bytes.end(), expected_client_id.begin())) {
            std::cout << "Client ID validated successfully." << std::endl;
        }
        else {
            std::cout << "Client ID validation failed." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error receiving response: " << e.what() << std::endl;
    }
}

//Function to receive the server's response for code 1605
std::vector<uint8_t> receive_response_1605(boost::asio::ip::tcp::socket& socket, const std::string& username) {
    std::vector<uint8_t> buffer(7); //1 byte version + 2 bytes code + 4 bytes payload size

    try {
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(buffer));
        if (bytes_read < buffer.size()) {
            throw std::runtime_error("Error: Received incomplete response header.");
        }

        //Extract version, code, and payload size
        uint8_t version = buffer[0];
        uint16_t code = (buffer[2] << 8) | buffer[1];
        uint32_t payload_size = (buffer[6] << 24) | (buffer[5] << 16) | (buffer[4] << 8) | buffer[3];

        if (code != 1605) {
            std::cout << "Received error code: " << code << ".\n";
            if (file_exists("me.info")) {
                std::remove("me.info");
                std::cout << "Deleted me.info.\n";
            }
            if (file_exists("priv.key")) {
                std::remove("priv.key");
                std::cout << "Deleted priv.key.\n";
            }
            throw std::runtime_error("Unexpected response code: " + std::to_string(code));
        }

        //Read the payload (client ID + encrypted AES key)
        std::vector<uint8_t> payload_buffer(payload_size);
        bytes_read = boost::asio::read(socket, boost::asio::buffer(payload_buffer));
        if (bytes_read < payload_buffer.size()) {
            throw std::runtime_error("Error: Received incomplete payload.");
        }

        //Decrypt AES key and return it
        return decrypt_aes_key_from_response(payload_buffer);
    }
    catch (const std::exception& e) {
        std::cerr << "Error receiving response: " << e.what() << std::endl;
        return {};  //Return an empty vector in case of error
    }
}

std::vector<uint8_t> decrypt_aes_key_from_response(const std::vector<uint8_t>& payload_buffer) {
    std::string received_client_id, stored_client_id;

    //Extract client_id from the payload and compare with me.info
    std::ostringstream received_client_id_hex;
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        received_client_id_hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload_buffer[i]);
    }
    received_client_id = received_client_id_hex.str();

    std::ifstream me_file("me.info");
    std::string stored_username;
    if (!std::getline(me_file, stored_username) || !std::getline(me_file, stored_client_id)) {
        throw std::runtime_error("Error reading me.info file.");
    }

    if (received_client_id != stored_client_id) {
        throw std::runtime_error("Client ID mismatch: received vs stored.");
    }

    std::cout << "Client ID matches. Decrypting AES key.\n";

    //Extract the encrypted AES key (remaining part of the payload after the client ID)
    std::vector<uint8_t> encrypted_aes_key_base64(payload_buffer.begin() + CLIENT_ID_SIZE, payload_buffer.end());

    //Base64 decode the encrypted AES key
    std::string encrypted_aes_key;
    CryptoPP::StringSource ss(encrypted_aes_key_base64.data(), encrypted_aes_key_base64.size(), true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(encrypted_aes_key)
        )
    );

    //Declare and initialize the RNG (Random Number Generator)
    CryptoPP::AutoSeededRandomPool rng;

    //Load the private RSA key
    CryptoPP::RSA::PrivateKey private_key;
    CryptoPP::ByteQueue bytes;
    CryptoPP::FileSource file("priv.key", true);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    private_key.Load(bytes);

    //Declare and initialize the RSA decryptor
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key);

    //Declare decrypted_aes_key to store the decrypted AES key
    std::string decrypted_aes_key;

    //Decrypt the AES key using the RSA private key
    CryptoPP::ArraySource as(reinterpret_cast<const CryptoPP::byte*>(encrypted_aes_key.data()), encrypted_aes_key.size(), true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(decrypted_aes_key)
        )
    );

    //Ensure the decrypted key is 256 bits (32 bytes)
    if (decrypted_aes_key.size() != 32) {
        throw std::runtime_error("Decrypted AES key is not 256 bits.");
    }

    //Convert decrypted key to byte vector and return
    return std::vector<uint8_t>(decrypted_aes_key.begin(), decrypted_aes_key.end());
}

void encrypt_file_with_aes(const std::string& file_name, const std::vector<uint8_t>& aes_key) {
    using namespace CryptoPP;

    //Read the original file contents
    std::ifstream input_file(file_name, std::ios::binary);
    if (!input_file.is_open()) {
        throw std::runtime_error("Error: Could not open file " + file_name);
    }

    std::vector<uint8_t> original_file_contents((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
    input_file.close();

    //Prepare IV (use zero-filled for AES-CBC mode)
    std::vector<uint8_t> iv(AES::BLOCKSIZE, 0);  //16-byte IV, filled with zero

    //AES-CBC encryption using the decrypted AES key
    CBC_Mode<AES>::Encryption encryptor(aes_key.data(), aes_key.size(), iv.data());

    //Encrypt the file contents and automatically add PKCS padding
    std::string cipher_text;
    StringSource(original_file_contents.data(), original_file_contents.size(), true,
        new StreamTransformationFilter(encryptor,
            new StringSink(cipher_text),
            StreamTransformationFilter::PKCS_PADDING //Enable PKCS padding
        )
    );

    //Overwrite the original file with the encrypted contents
    std::ofstream encrypted_file(file_name, std::ios::binary); //Overwrite original file
    if (!encrypted_file.is_open()) {
        throw std::runtime_error("Error: Could not open file to write encrypted data.");
    }
    encrypted_file.write(cipher_text.data(), cipher_text.size());
    encrypted_file.close();

    std::cout << "File encrypted and overwritten successfully." << std::endl;
}

void load_encrypted_file_into_vector(const std::string& encrypted_file_name, std::vector<uint8_t>& encrypted_data) {
    //Open the encrypted file
    std::ifstream encrypted_file(encrypted_file_name, std::ios::binary);
    if (!encrypted_file.is_open()) {
        throw std::runtime_error("Failed to open the encrypted file for reading.");
    }

    //Get the size of the encrypted file
    size_t encrypted_file_size = std::filesystem::file_size(encrypted_file_name);

    //Resize the vector to fit the encrypted data
    encrypted_data.resize(encrypted_file_size);

    //Read the file content into the vector
    encrypted_file.read(reinterpret_cast<char*>(encrypted_data.data()), encrypted_file_size);

    //Close the file
    encrypted_file.close();

    std::cout << "Encrypted file data successfully loaded into encrypted_data vector.\n";
}

void send_encrypted_file_in_packets(const std::string& client_id_str, uint16_t code, const std::vector<uint8_t>& encrypted_data, size_t original_file_size, const std::string& file_name, boost::asio::ip::tcp::socket& socket) {
    //Calculate total packets
    uint16_t total_packets = static_cast<uint16_t>((encrypted_data.size() + PACKET_SIZE - 1) / PACKET_SIZE);  //Round up division
    //Send each packet
    for (uint16_t packet_number = 1; packet_number <= total_packets; ++packet_number) {
        //Calculate the start and end index of the current packet's data
        size_t start_index = (packet_number - 1) * PACKET_SIZE;
        size_t end_index = std::min(start_index + PACKET_SIZE, encrypted_data.size());

        //Get the current packet's data slice
        std::vector<uint8_t> packet_data(encrypted_data.begin() + start_index, encrypted_data.begin() + end_index);

        //Construct the message for the current packet
        std::vector<uint8_t> message = construct_message_with_encrypted_file(
            client_id_str, code, packet_data, original_file_size, file_name, packet_number, total_packets
        );

        boost::asio::write(socket, boost::asio::buffer(message));
        std::cout << "Packet " << packet_number << " of " << total_packets << " sent. Size: " << packet_data.size() << " bytes." << std::endl;
    }

}

//Guy Rav On 315044743

#include "client_request.h"
#include "RSA_keys_handling.h"
#include "file_handling.h"
#include "crc_checksum.h"

int main() {
    try {
        //Read IP, port, and username from transfer.info
        auto [ip, port] = read_ip_port_from_file("transfer.info");
        auto [username, file_name] = read_username_and_file_from_file("transfer.info");

        std::vector<uint8_t> message;
        std::string client_id;

        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::ip::tcp::socket socket(io_context);

        std::vector<uint8_t> aes_key;

        //Check if me.info exists
        if (!file_exists("me.info")) {
            std::cout << "First connection, sending registration message (code 825)...\n";

            //First connection: construct message with client_id = 0, code = 825, payload = username
            message = construct_message("", 825, username);

            //Resolve the endpoint and connect
            boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
            try {
                boost::asio::connect(socket, endpoints);
                std::cout << "Connected to server at " << ip << ":" << port << std::endl;
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error: Failed to connect to server at " + ip + ":" + port + ". " + e.what());
            }

            std::cout << "Connected to server at " << ip << ":" << port << std::endl;

            //Send the registration message (code 825)
            try {
                boost::asio::write(socket, boost::asio::buffer(message));
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
            }

            std::cout << "Registration message sent (code 825)." << std::endl;

            //Receive and handle the server's response (code 1600 expected)
            receive_response_1600(socket, username);

            //Read the client_id from me.info file after receiving the response
            std::ifstream me_file("me.info");
            if (!std::getline(me_file, username) || !std::getline(me_file, client_id)) {
                throw std::runtime_error("Error: Unable to read client_id from me.info");
            }

            std::cout << "Client ID read from me.info: " << client_id << "\n";

            //Close the socket after receiving the response
            socket.close();

            //Generate RSA keys and save the private key to priv.key
            std::string public_key_base64 = generate_and_save_rsa_keys();

            //Now send the public key with code 826
            std::cout << "Sending public key with registration (code 826)...\n";
            message = construct_message_with_public_key(826, username, public_key_base64);

            //Reconnect to send the message with public key (code 826)
            try {
                boost::asio::connect(socket, endpoints);
                std::cout << "Connected to server at " << ip << ":" << port << std::endl;
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error: Failed to connect to server at " + ip + ":" + port + ". " + e.what());
            }

            try {
                boost::asio::write(socket, boost::asio::buffer(message));
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
            }

            std::cout << "Message with public key sent (code 826)." << std::endl;

            //Receive the server's response message 1602 and decrypt the AES key
            aes_key = receive_response_1602(socket, username);
            socket.close();  //Close the socket after sending the public key
        }
        else {
            //Regular connection with me.info present
            std::cout << "Regular connection, me.info found.\n";

            //Read client_id and username from me.info
            std::ifstream me_file("me.info");
            if (!std::getline(me_file, username) || !std::getline(me_file, client_id)) {
                throw std::runtime_error("Error: Unable to read client_id from me.info");
            }

            std::cout << "Read client_id from me.info: " << client_id << "\n";

            //Construct and send the 827 message
            message = construct_message_with_client_id(827, client_id, username);

            //Resolve the endpoint and connect
            boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
            try {
                boost::asio::connect(socket, endpoints);
                std::cout << "Connected to server at " << ip << ":" << port << std::endl;
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error: Failed to connect to server at " + ip + ":" + port + ". " + e.what());
            }

            std::cout << "Connected to server at " << ip << ":" << port << std::endl;

            //Send the 827 message
            try {
                boost::asio::write(socket, boost::asio::buffer(message));
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
            }
            std::cout << "Message 827 sent with client_id and username: " << client_id << " " << username << std::endl;

            //Receive the server's response message 1605 and decrypt the AES key
            aes_key = receive_response_1605(socket, username);
            socket.close();  //Close the socket after sending the message
        }

        //Calculate the CRC and file size before encryption
        unsigned long crc_value = 0;
        size_t file_size = 0;

        //Read file and calculate CRC
        std::ifstream file(file_name, std::ios::binary);
        if (file.is_open()) {
            file_size = std::filesystem::file_size(file_name);
            std::vector<char> buffer(file_size);
            file.read(buffer.data(), file_size);

            crc_value = memcrc(buffer.data(), file_size);
            file.close();

            std::cout << "CRC of file " << file_name << ": " << std::hex << crc_value << std::dec << std::endl;
            std::cout << "File size: " << file_size << " bytes" << std::endl;
        }
        else {
            std::cerr << "Failed to open file for CRC calculation.\n";
            return 1;
        }

        //Encrypt the file using the decrypted AES key
        std::cout << "AES Key is ready for use.\n";
        encrypt_file_with_aes(file_name, aes_key);

        //Load the encrypted data from the file into a vector
        std::vector<uint8_t> encrypted_data;
        load_encrypted_file_into_vector(file_name, encrypted_data);

        //Reconnect the socket and send the encrypted file in packets
        if (!socket.is_open()) {
            boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, port);
            try {
                boost::asio::connect(socket, endpoints);
                std::cout << "Connected to server at " << ip << ":" << port << std::endl;
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error: Failed to connect to server at " + ip + ":" + port + ". " + e.what());
            }

            std::cout << "Reconnected to server for sending the encrypted file.\n";
        }

        //Call the function to send the encrypted file in packets
        send_encrypted_file_in_packets(client_id, 828, encrypted_data, file_size, file_name, socket);

        std::cout << "All packets sent successfully (code 828).\n";

        //Assuming crc_value is already defined and has the expected CRC value
        uint32_t crc_response = receive_response_1603(socket, username);

        if (crc_response == crc_value) {
            std::cout << "CRC values match!" << std::endl;

            //Construct the message with file name
            std::vector<uint8_t> request_message = construct_message_with_file_name(900, file_name);

            //Send the request to the server
            try {
                boost::asio::write(socket, boost::asio::buffer(request_message));
            }
            catch (const boost::system::system_error& e) {
                throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
            }
            std::cout << "Request with code 900 sent successfully." << std::endl;

            //Now wait for the response with code 1604
            receive_response_1604(socket);
        }
        else {
            std::cout << "CRC values do not match! Attempting to resend." << std::endl;
            bool transfer_successful = false;
            //Attempt to resend up to four times
            for (int attempt = 1; attempt <= 4; ++attempt) {
                std::cout << "Resending request with code 901, attempt " << attempt << "..." << std::endl;

                //Construct the message for code 901
                std::vector<uint8_t> request_message = construct_message_with_file_name(901, file_name);
                try {
                    boost::asio::write(socket, boost::asio::buffer(request_message));
                }
                catch (const boost::system::system_error& e) {
                    throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
                }

                //Attempt to resend the original request with code 828
                bool transfer_successful = false; //Track if the transfer was successful

                try {
                    send_encrypted_file_in_packets(client_id, 828, encrypted_data, file_size, file_name, socket);
                    transfer_successful = true; //If no exception, transfer was successful
                    std::cout << "File transfer successful on attempt " << attempt << "." << std::endl;
                    break; //Exit the loop if transfer is successful
                }
                catch (const std::exception& e) {
                    std::cout << "File transfer failed on attempt " << attempt << ": " << e.what() << std::endl;
                }
            }

            //If after four attempts it still fails, send code 902
            if (!transfer_successful) {
                std::cout << "All attempts failed. Sending request with code 902." << std::endl;

                std::vector<uint8_t> request_message = construct_message_with_file_name(902, file_name);
                try {
                    boost::asio::write(socket, boost::asio::buffer(request_message));
                }
                catch (const boost::system::system_error& e) {
                    throw std::runtime_error("Error sending data to server: " + std::string(e.what()));
                }

                //Wait for the server's response to code 902
                receive_response_1604(socket);
            }
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

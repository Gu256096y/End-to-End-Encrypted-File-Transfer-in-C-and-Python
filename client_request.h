//Guy Rav On 315044743

#ifndef CLIENT_REQUEST_H
#define CLIENT_REQUEST_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <boost/asio.hpp>
#include <filters.h>
#include <hex.h>
#include <iostream>
#include <stdexcept>
#include <fstream>

//Constants
const uint8_t VERSION = 0x03;             //Version is always 0x03
const size_t CLIENT_ID_SIZE = 16;         //Client ID size is always 16 bytes
const size_t CODE_SIZE = 2;               //Code size is 2 bytes
const size_t PAYLOAD_SIZE_FIELD_SIZE = 4; //Payload size field is 4 bytes
const size_t REGISTRATION_PAYLOAD_SIZE = 255; //Payload size for registration
const size_t PACKET_SIZE = 1024; //Define packet size (1 KB)

//Function to construct a message with the given parameters
std::vector<uint8_t> construct_message(const std::string& client_id_str, uint16_t code, const std::string& payload);

//message 826
std::vector<uint8_t> construct_message_with_public_key(uint16_t code, const std::string& username, const std::string& public_key_base64);

//message 827
std::vector<uint8_t> construct_message_with_client_id(uint16_t code, const std::string& client_id_str, const std::string& username);

//Function to construct message for file request (code 900)
std::vector<uint8_t> construct_message_with_file_name(uint16_t code, const std::string& file_name);

//Function to receive the server's response for code 1604
void receive_response_1604(boost::asio::ip::tcp::socket& socket);

//Function to receive the server's response
uint32_t receive_response_1603(boost::asio::ip::tcp::socket& socket, const std::string& username);

//Function to receive the server's response
std::vector<uint8_t> receive_response_1602(boost::asio::ip::tcp::socket& socket, const std::string& username);

//Function to receive the server's response for code 1600
void receive_response_1600(boost::asio::ip::tcp::socket& socket, const std::string& username);

//Function to receive the server's response for code 1605
std::vector<uint8_t> receive_response_1605(boost::asio::ip::tcp::socket& socket, const std::string& username);

//Function to handle aes key decrypt
std::vector<uint8_t> decrypt_aes_key_from_response(const std::vector<uint8_t>& payload_buffer);

//Function to encrypt the file using AES-CBC
void encrypt_file_with_aes(const std::string& file_name, const std::vector<uint8_t>& aes_key);

//Function to construct and send the encrypted file in packets (code 828)
std::vector<uint8_t> construct_message_with_encrypted_file(const std::string& client_id_str, uint16_t code, const std::vector<uint8_t>& encrypted_data, size_t original_file_size, const std::string& file_name, uint16_t packet_number, uint16_t total_packets);

void load_encrypted_file_into_vector(const std::string& encrypted_file_name, std::vector<uint8_t>& encrypted_data);

void send_encrypted_file_in_packets(const std::string& client_id_str, uint16_t code, const std::vector<uint8_t>& encrypted_data, size_t original_file_size, const std::string& file_name, boost::asio::ip::tcp::socket& socket);

#endif //CLIENT_REQUEST_H

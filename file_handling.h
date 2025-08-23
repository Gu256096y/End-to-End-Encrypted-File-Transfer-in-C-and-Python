//Guy Rav On 315044743

#ifndef FILE_HANDLING_H
#define FILE_HANDLING_H

#include <string>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <iostream>

const size_t MAX_USERNAME_SIZE = 100;     //Maximum username size is 100 characters

//Function to read IP and port from transfer.info
std::pair<std::string, std::string> read_ip_port_from_file(const std::string& filename);

//Function to read the username from transfer.info
std::pair<std::string, std::string> read_username_and_file_from_file(const std::string& filename);

//Function to check if a file exists
bool file_exists(const std::string& filename);

#endif //FILE_HANDLING_H
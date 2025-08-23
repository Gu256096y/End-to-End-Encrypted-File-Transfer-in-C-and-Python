//Guy Rav On 315044743

#include "file_handling.h"

//Function to check if a file exists
bool file_exists(const std::string& filename) {
    return std::filesystem::exists(filename);  //Use std::filesystem directly
}

//Function to read IP and port from transfer.info
std::pair<std::string, std::string> read_ip_port_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Could not open file " + filename);
    }

    std::string line;
    if (std::getline(file, line)) {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string ip = line.substr(0, colon_pos);
            std::string port = line.substr(colon_pos + 1);

            try {
                //Validate port number
                int port_num = std::stoi(port);
                if (port_num < 1 || port_num > 65535) {
                    throw std::runtime_error("Error: Invalid port number in " + filename);
                }
                return { ip, port };
            }
            catch (const std::invalid_argument& e) {
                throw std::runtime_error("Error: Port is not a valid number in " + filename);
            }
            catch (const std::out_of_range& e) {
                throw std::runtime_error("Error: Port number out of range in " + filename);
            }

        }
        else {
            throw std::runtime_error("Error: Invalid format (missing colon) in " + filename);
        }
    }
    else {
        throw std::runtime_error("Error: Could not read from file " + filename);
    }
}

//Function to read the username and file name from transfer.info
std::pair<std::string, std::string> read_username_and_file_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Could not open file " + filename);
    }

    std::string ip_port, username, file_name;

    //Read the first two lines (IP and port, username)
    if (std::getline(file, ip_port) && std::getline(file, username) && std::getline(file, file_name)) {
        //Truncate username to 100 characters if it's longer
        if (username.size() > MAX_USERNAME_SIZE) {
            username.resize(MAX_USERNAME_SIZE);  //Modify in place for efficiency
        }

        //Validate username (basic example: not empty)
        if (username.empty()) {
            throw std::runtime_error("Error: Username is empty in " + filename);
        }

        return { username, file_name }; //Return username and file name
    }
    else {
        throw std::runtime_error("Error: Invalid format or missing username/file name in " + filename);
    }
}
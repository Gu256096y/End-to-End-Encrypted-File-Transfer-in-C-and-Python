//Guy Rav On 315044743

#ifndef CRC_CHECKSUM_H
#define CRC_CHECKSUM_H

#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>

//Function to calculate the CRC checksum of a memory buffer
unsigned long memcrc(char* b, size_t n);

//Function to read a file and return its CRC checksum and size
std::string readfile(std::string fname);

#endif //CRC_CHECKSUM_H


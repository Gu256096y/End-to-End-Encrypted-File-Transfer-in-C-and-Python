//Guy Rav On

#ifndef RSA_KEYS_HANDLING_H
#define RSA_KEYS_HANDLING_H

#include <string>
#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include <base64.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <cryptlib.h>

//Function to generate RSA keys and save them
std::string generate_and_save_rsa_keys();

#endif //RSA_KEYS_HANDLING_H


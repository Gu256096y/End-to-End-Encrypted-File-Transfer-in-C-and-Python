//Guy Rav On 315044743

#include "RSA_keys_handling.h"

//Function to generate RSA keys and save them
std::string generate_and_save_rsa_keys() {
    using namespace CryptoPP;
    std::string publicKeyBase64;

    try {
        //Generate RSA keys
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;

        //Generate a 1024-bit private key
        privateKey.GenerateRandomWithKeySize(rng, 1024);
        publicKey.AssignFrom(privateKey);  //Derive public key from private key

        //Save the private key in DER format (no Base64 encoding for priv.key file)
        std::string privateKeyDER;
        StringSink privSink(privateKeyDER);
        privateKey.DEREncode(privSink);
        privSink.MessageEnd();

        //Write the private key to priv.key (DER format, no Base64 encoding)
        std::ofstream privFile("priv.key", std::ios::binary);
        if (!privFile.is_open()) {
            throw std::runtime_error("Failed to create priv.key.");
        }
        privFile.write(privateKeyDER.data(), privateKeyDER.size());
        privFile.close();
        std::cout << "Private key saved to priv.key in binary format." << std::endl;

        //Encode the private key in Base64 without line breaks for saving to me.info
        std::string privateKeyBase64;
        StringSource(privateKeyDER, true,
            new Base64Encoder(
                new StringSink(privateKeyBase64),
                false  //Set 'false' to disable line breaks in Base64 encoding
            )
        );

        //Save the private key (Base64-encoded) to the third line of me.info
        std::ifstream meFileCheck("me.info");
        if (!meFileCheck.is_open()) {
            throw std::runtime_error("Failed to open me.info for checking.");
        }

        int line_count = 0;
        std::string line;
        while (std::getline(meFileCheck, line)) {
            line_count++;
        }
        meFileCheck.close();

        if (line_count < 3) {
            std::ofstream meFile("me.info", std::ios_base::app);
            if (!meFile.is_open()) {
                throw std::runtime_error("Failed to open me.info to save the private key.");
            }
            meFile << privateKeyBase64 << "\n";
            meFile.close();
            std::cout << "Private key saved to the third line of me.info in a single line." << std::endl;
        }

        //Encode the public key in Base64
        std::string publicKeyDER;
        StringSink pubSink(publicKeyDER);
        publicKey.DEREncode(pubSink);
        pubSink.MessageEnd();

        StringSource(publicKeyDER, true,
            new Base64Encoder(
                new StringSink(publicKeyBase64),
                false  //Set 'false' to disable line breaks in Base64 encoding
            )
        );

        std::cout << "Public key generated and base64-encoded." << std::endl;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "CryptoPP exception: " << e.what() << std::endl;
        throw;  //Re-throw after logging
    }
    catch (const std::exception& e) {
        std::cerr << "Standard exception during key generation: " << e.what() << std::endl;
        throw;  //Re-throw after logging
    }

    return publicKeyBase64;  //Return the base64-encoded public key
}
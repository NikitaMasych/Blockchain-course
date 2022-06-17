#include <iostream>
#include <iomanip>
#include "AES.h"


size_t convertKeyLength(std::string str){
    std::string error = "Invalid key length!\n";
    if (str.length() != 3) throw std::invalid_argument(error);
    if (!std::isdigit(str[0]) || !std::isdigit(str[1]) || !std::isdigit(str[2]))
        throw std::invalid_argument(error);
    size_t num = std::stoul(str);
    if (num != 128 && num != 192 && num != 256)
        throw std::invalid_argument("Key length out of range!\n");
    return num;
}

void AES::enterKeyLength(){
    std::cout << "Enter key length: ";
    std::string str;
    std::getline(std::cin, str);
    try{
        keyLen = convertKeyLength(str);

        switch(keyLen){
        case 128:
            {
              Nk = 4; Nr = 10; break;
            }
        case 192:
            {
              Nk = 6; Nr = 12; break;
            }
        case 256:
            {
              Nk = 8; Nr = 14; break;
            }
        }
    }
    catch(std::invalid_argument& e){
        std::cerr << e.what();
        enterKeyLength();
    }
};

void AES::enterKey(){
    std::cout << "Enter key in hex: ";
    std::string str;
    try{
        std::getline(std::cin, str);
        std::vector<uint_fast8_t> res;
        // divide by 4 because key in hex
        if (str.length() != keyLen / 4) throw std::invalid_argument("Invalid key size!\n");
        for (size_t i = 0; i < str.length(); i += 2){
            if (!( isxdigit(str[i]) && isxdigit(str[i+1])))
                throw std::invalid_argument("Not hexadecimal character detected!\n");
            std::string byte = str.substr(i, 2);
            res.push_back(static_cast<uint_fast8_t>(std::stoul(byte, nullptr, 16)));
        }
        key = res;
    }
    catch(std::exception& e){
        std::cerr << e.what();
        enterKey();
    }
}

void AES::requestKey(){
    enterKeyLength();
    enterKey();
};

void AES::enterPlaintext(){
    std::cout << "Enter ASCII plaintext to encrypt: ";
    std::string str;
    try{
        std::getline(std::cin, str);
        if (str.size() % 16 != 0){
            throw std::invalid_argument("Plaintext length is not divisible by 16!\n");
        }
        for (uint_fast8_t c : str){
            if (c > 127)
                throw std::invalid_argument("Invalid character detected!\n");

            plaintext.push_back(c);
        }
    }
    catch(std::invalid_argument& e){
        std::cerr << e.what();
        plaintext.clear();
        enterPlaintext();
    }
};

void AES::outputExpandedKeys(){
    for(size_t i = 0; i != key.size(); i += 4){
        std::cout << std::dec << "Key " << i/4 << " : ";
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint_fast16_t>(key[i]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint_fast16_t>(key[i+1]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint_fast16_t>(key[i+2]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint_fast16_t>(key[i+3]);
        std::cout << '\n';
    }
}

void AES::outputPlaintext(){
    std::cout << "Plaintext: ";
    for (unsigned char c: plaintext)std::cout << c;
    std::cout << '\n';
};

void AES::outputCiphertext(){
    std::cout << "Ciphertext: ";
    for (unsigned char c: ciphertext)std::cout <<
        std::setw(2) << std::setfill('0') << std::hex << static_cast<uint_fast16_t>(c);
    std::cout << '\n';
};

std::vector <uint_fast8_t> AES::getPlaintext(){
    return plaintext;
};

std::vector <uint_fast8_t> AES::getCiphertext(){
    return ciphertext;
}

void AES::initializeSBox(){
    std::vector <std::vector <uint_fast8_t> > SBOX
    {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
    sBox = SBOX;
}

AES::AES(){
    initializeSBox();
}

void AES::enterPlaintextAsHex(){
    std::cout << "Enter plaintext in hex: ";
    std::string str;
    try{
        std::getline(std::cin, str);
        std::vector<uint_fast8_t> res;
        // doubling 16 bytes block due to hex representation
        if (str.length() % 32 != 0) throw std::invalid_argument("Invalid plaintext size!\n");
        for (size_t i = 0; i < str.length(); i += 2){
            if (!( isxdigit(str[i]) && isxdigit(str[i+1])))
                throw std::invalid_argument("Not hexadecimal character detected!\n");
            std::string byte = str.substr(i, 2);
            res.push_back(static_cast<uint_fast8_t>(std::stoul(byte, nullptr, 16)));
        }
        plaintext = res;
    }
    catch(std::exception& e){
        std::cerr << e.what();
        enterPlaintextAsHex();
    }
};

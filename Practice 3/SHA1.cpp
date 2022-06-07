#include <iostream>
#include <vector>
#include <iomanip>
#include "SHA1.h"


uint_fast32_t binaryRepresentation(std::string str){
    // converts 4 characters string to 32 binary
    return (int(str[0]) << 24) | (int(str[1]) << 16) | (int(str[2]) << 8) | int(str[3]);
}

uint_fast32_t leftRotate(uint_fast32_t a, unsigned int c){
    // implements c bites circular left shift for value a
    unsigned int INT_BITS = 32;
    return (a << c)|(a >> (INT_BITS - c));
}

std::string stringRepresentation(uint_fast32_t a){
    // converts 32 binary to hexadecimal string
    uint_fast32_t completeByte = 0xFF;

    std::stringstream stream;
    stream << std::hex << ((a >> 24) & completeByte)
                       << ((a >> 16) & completeByte)
                       << ((a >> 8)  & completeByte)
                       <<  (a        & completeByte);

    return stream.str();
}

std::string hashLinker(uint_fast32_t h0, uint_fast32_t h1,
                       uint_fast32_t h2, uint_fast32_t h3,
                       uint_fast32_t h4){
    // generates hexadecimal string as hashing result
    std::string res = "";
    res += stringRepresentation(h0);
    res += stringRepresentation(h1);
    res += stringRepresentation(h2);
    res += stringRepresentation(h3);
    res += stringRepresentation(h4);
    return res;
}

std::vector <uint_fast32_t> SHA1::wordsGenerator(size_t& pos){
    std::vector <uint_fast32_t> words;
    // get 16 words 4 character each = 32 bites
    for(; pos != 64; pos += 4){
        uint_fast32_t word = binaryRepresentation(value.substr(pos, 4));
        words.push_back(word);
    }
    // get another 64 words based on those 16
    for (size_t i = 16; i != 80; ++i){
        uint_fast32_t word = leftRotate((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i - 16]), 1);
        words.push_back(word);
    }
    return words;
}

void processVals(uint_fast32_t& a, uint_fast32_t& b,
                 uint_fast32_t& c, uint_fast32_t& d,
                 uint_fast32_t& e, const std::vector <uint_fast32_t> &words){
    for (size_t i = 0; i != 80; ++i){
        uint_fast32_t k, f;
        if (i < 20){
            f = (b && c) || ((!b) && d);
            k = 0x5A827999;
        }
        else if (i < 40){
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60){
            f = (b || c) || (b && d) || (c && d);
            k = 0x8F1BBCDC;
        }
        else{
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint_fast32_t temp = leftRotate(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = leftRotate(b, 30);
        b = a;
        a = temp;
    }

}

void SHA1::HashForChunk(uint_fast32_t& h0, uint_fast32_t&  h1,
                        uint_fast32_t& h2, uint_fast32_t&  h3,
                        uint_fast32_t& h4, size_t& pos){
    // break chunk into 16 + 64 words:
    std::vector <uint_fast32_t> words = wordsGenerator(pos);

    // initialize hash values for this chunk:
    uint_fast32_t a, b, c, d, e;
    a = h0;
    b = h1;
    c = h2;
    d = h3;
    e = h4;

    processVals(a, b, c, d, e, words);

    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;

}

void SHA1::generateLastChunk(){
    // as far as we storing value in characters, which are one byte
    // adding 1 is possible only as adding 10000000 - ASCII A code
    value += "A";

    size_t zerosAmount;
    size_t non512Characters = value.length() % 64;

    if (non512Characters <= 55) zerosAmount = 440 - non512Characters * 8;
    else zerosAmount = (64 - non512Characters - 1) * 8 + (512 - 64);

    for (size_t i = 0; i != zerosAmount; i += 8)
        value += static_cast<char>(0b00000000);

    // 64 bit length of the initial message
    uint_fast64_t len = value.length() * 8; // in bits
    uint_fast32_t fourByte = 0xFFFFFFFFFFFFFFFF;
    std::string l = stringRepresentation((len >> 32) & fourByte) +
                    stringRepresentation(len & fourByte);
    value += l;
}

void SHA1::calculateHash(){
    uint_fast32_t h0, h1, h2, h3, h4;
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;

    size_t pos = 0;
    generateLastChunk();
    while (pos < value.length()){
        HashForChunk(h0, h1, h2, h3, h4, pos);
    }
    hashValue = hashLinker(h0, h1, h2, h3, h4);
}

void SHA1::outputHash(){
    std::cout << "For given value, hash is: \n" <<  hashValue;
}

void SHA1::enterValue(){
    std::cout << "Enter value: ";
    std::getline(std::cin, value);
}
std::string SHA1::getHash(){
    return hashValue;
}
SHA1::SHA1(){
    enterValue();
    calculateHash();
}

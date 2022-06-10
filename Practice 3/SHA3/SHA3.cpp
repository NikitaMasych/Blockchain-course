#include <iostream>
#include "SHA3.h"


void SHA3::initialiseRC(){
    // sets round constants
    std::vector<uint_fast64_t> RC(24);
    RC[0]  = 0x0000000000000001; RC[12] = 0x000000008000808B;
    RC[1]  = 0x0000000000008082; RC[13] = 0x800000000000008B;
    RC[2]  = 0x800000000000808A; RC[14] = 0x8000000000008089;
    RC[3]  = 0x8000000080008000; RC[15] = 0x8000000000008003;
    RC[4]  = 0x000000000000808B; RC[16] = 0x8000000000008002;
    RC[5]  = 0x0000000080000001; RC[17] = 0x8000000000000080;
    RC[6]  = 0x8000000080008081; RC[18] = 0x000000000000800A;
    RC[7]  = 0x8000000000008009; RC[19] = 0x800000008000000A;
    RC[8]  = 0x000000000000008A; RC[20] = 0x8000000080008081;
    RC[9]  = 0x0000000000000088; RC[21] = 0x8000000000008080;
    RC[10] = 0x0000000080008009; RC[22] = 0x0000000080000001;
    RC[11] = 0x000000008000000A; RC[23] = 0x8000000080008008;
    SHA3::RC = RC;
}

void SHA3::initialiseRO(){
    std::vector<std::vector<uint_fast64_t> > RO{
        {0, 1, 62, 28, 27},
        {36, 44, 6, 55, 20},
        {3, 10, 43, 25, 39},
        {41, 45, 15, 21, 8},
        {18, 2, 61, 56, 14},
    };
    SHA3::RO = RO;
}

uint_fast64_t leftRotate(uint_fast64_t a, unsigned int c){
    // implements c bits circular left shift for value a
    unsigned int INT_BITS = 64;
    return (a << c)|(a >> (INT_BITS - c));
}

void theta(std::vector<std::vector<uint_fast64_t> > &A){
    std::vector<uint_fast64_t> C(5);
    for (size_t i = 0; i != 5; ++i)
        C[i] = (A[i][0] ^ A[i][1] ^ A[i][2] ^ A[i][3] ^ A[i][4]);

    std::vector<uint_fast64_t> D(5);
    for (size_t i = 0; i != 5; ++i)
        D[i] = (C[(i+4) % 5] ^ leftRotate(C[(i+1) % 5], 1));

    for (size_t i = 0; i != 5; ++i){
        for (size_t j = 0; j != 5; ++j)
            A[i][j] = (A[i][j] ^ D[i]);
    }
}

std::vector <std::vector <uint_fast64_t> > SHA3::rhoAndPi(std::vector<std::vector<uint_fast64_t> > &A){
    std::vector <std::vector <uint_fast64_t> > B (5, std::vector<uint_fast64_t>(5));
    for(size_t i = 0; i != 5; ++i){
        for(size_t j = 0; j!= 5; ++j){
            B[j][(2*i + 3*j) % 5] = leftRotate(A[i][j], RO[i][j]);
        }
    }
    return B;
}

void chi(std::vector <std::vector <uint_fast64_t> > &A,
         const std::vector <std::vector <uint_fast64_t> > &B){
    for(size_t i = 0; i != 5; ++i){
        for(size_t j = 0; j != 5; ++j){
            A[i][j] = (B[i][j] ^ ((~B[(i+1) % 5][j]) & B[(i+2) % 5][j]));
        }
    }
}

void iota(std::vector <std::vector <uint_fast64_t> > &A, uint_fast64_t rc){
    A[0][0] = A[0][0] ^ rc;
}

void SHA3::round(std::vector<std::vector<uint_fast64_t> > &A, uint_fast64_t rc){

    // Theta:
    theta(A);
    std::vector <std::vector <uint_fast64_t> > B = rhoAndPi(A);
    chi(A, B);
    iota(A, rc);
}

void SHA3::keccakF(std::vector<std::vector<uint_fast64_t> > &A){
    for(size_t i = 0; i != 24; ++i){
        round(A, RC[i]);
    }
}

void SHA3::padding(){
    c = bitsDigest * 2; // capacity
    r = 1600 - c; // rate
    // total number of appended bytes
    size_t q = (r/8) - (message.size() % (r/8));

    switch(q){
    case 1:
        message.push_back(static_cast<unsigned char>(0x86));
        break;
    case 2:
    {
        message.push_back(static_cast<unsigned char>(0x06));
        message.push_back(static_cast<unsigned char>(0x80));
        break;
    }
    default:
    {
        message.push_back(static_cast<unsigned char>(0x06));
        for (size_t i = 0; i != q - 2; ++i)
            message.push_back(static_cast<unsigned char>(0x00));
        message.push_back(static_cast<unsigned char>(0x80));
    }
    }
}

void SHA3::absorbing(){
    // initializing state array:
    std::vector<std::vector<uint_fast64_t> > sArray(5, std::vector<uint_fast64_t> (5,0));
    SHA3::stateArray = sArray;



}

void SHA3::calculateHash(){
    padding();
    absorbing();
    //squeezing();
}

void SHA3::enterMessage(){
    std::cout << "Enter ASCII string to hash: ";
    std::string str;
    std::getline(std::cin, str);
    for (unsigned char c: str) {
        // check whether symbol is not ASCII:
        if (c > 127){
            std::cout << "Inappropriate input!\n";
            message.clear();
            enterMessage();
            break;
        }
        message.push_back(c);
    }
}

size_t convertBitLength(std::string str){
    if (str.length() != 3) throw std::invalid_argument("Invalid input!\n");
    if (!std::isdigit(str[0]) || !std::isdigit(str[1]) || !std::isdigit(str[2]))
        throw std::invalid_argument("Invalid input!\n");
    size_t num = std::stoul(str);
    if (num != 224 && num != 256 && num != 384 && num != 512)
        throw std::invalid_argument("Invalid input!\n");
    return num;
}

void SHA3::enterBitDigest(){
    std::cout << "Enter desired digest length (in bits): ";
    std::string str;
    std::getline(std::cin, str);
    try{
        bitsDigest = convertBitLength(str);
    }
    catch (std::invalid_argument& e){
        std::cerr << e.what();
        enterBitDigest();
    }
}

std::string SHA3::getHash(){
    return messageDigest;
}

SHA3::SHA3(){
    initialiseRC();
    initialiseRO();
}

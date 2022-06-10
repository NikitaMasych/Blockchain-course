#ifndef SHA3_H_INCLUDED
#define SHA3_H_INCLUDED

#include <vector>

class SHA3{
private:
    std::string messageDigest;
    size_t bitsDigest;
    std::vector<unsigned char> message;
    void padding();
    void absorbing();
    void squeezing();
    size_t r, c;
    size_t b = 1600;
    size_t rounds = 24;
    size_t w = 64;
    std::vector<std::vector<uint_fast64_t> > stateArray;
    void kessakF();
    std::vector<uint_fast64_t> RC; // round constants
    std::vector<std::vector<uint_fast64_t> > RO; // rotation offsets
    std::vector <std::vector <uint_fast64_t> > rhoAndPi(std::vector<std::vector<uint_fast64_t> > &A);
    void round(std::vector<std::vector<uint_fast64_t> > &A,  uint_fast64_t rc);
    void keccakF(std::vector<std::vector<uint_fast64_t> > &A);

public:
    SHA3();
    void enterMessage();
    void enterBitDigest();
    void calculateHash();
    std::string getHash();
    void initialiseRC();
    void initialiseRO();
};

#endif // SHA3_H_INCLUDED

#ifndef SHA1_H
#define SHA1_H

#include <vector>

class SHA1{
    private:
        std::string hashValue;
        std::string value;
        std::vector <uint_fast32_t> wordsGenerator(size_t &pos);
        void generateLastChunk();
        void HashForChunk(uint_fast32_t& h0, uint_fast32_t&  h1,
                          uint_fast32_t& h2, uint_fast32_t&  h3,
                          uint_fast32_t& h4, size_t& pos);
    public:
        SHA1();
        void enterValue();
        void calculateHash();
        void outputHash();
        std::string getHash();
};

#endif

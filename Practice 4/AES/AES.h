#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <vector>


class AES{
private:
    std::vector <uint_fast8_t> plaintext, ciphertext, key;
    std::vector <uint_fast32_t> words; // expanded key
    size_t keyLen;
    size_t Nk, Nr;
    std::vector<std::vector<uint_fast8_t> > sBox;
    void enterKey();
    void enterKeyLength();
    void initializeSBox();
    void keyExpansion();
    void subWord(std::vector<uint_fast8_t> &temp);
    std::vector<std::vector<uint_fast8_t> > calculateBlock(size_t pos);
    void calculateCiphertext(
         std::vector <std::vector<std::vector<uint_fast8_t> > > cipher);
    void addRoundKey(std::vector<std::vector<uint_fast8_t> > &state,
                     size_t pos);
    void subBytes(std::vector<std::vector<uint_fast8_t> > &state);
public:
    void requestKey();
    void enterPlaintext();
    void enterPlaintextAsHex();
    void encryptPlaintext();
    void decryptCiphertext();
    void outputPlaintext();
    void outputCiphertext();
    void outputExpandedKeys();
    std::vector <uint_fast8_t> getPlaintext();
    std::vector <uint_fast8_t> getCiphertext();
    AES();
};

#endif // AES_H_INCLUDED

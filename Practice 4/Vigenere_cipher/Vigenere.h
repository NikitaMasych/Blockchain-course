#ifndef VIGENERE_H_INCLUDED
#define VIGENERE_H_INCLUDED

#include <string>


class Vigenere{
private:
    std::string plainText;
    std::string cipherText;
    std::string key;
public:
    void enterPlainText();
    void enterCipherText();
    void enterKey();
    void encryptPlainText();
    void decryptCipherText();
    void outputCipherText();
    void outputPlainText();
    std::string getCipherText();
    std::string getPlainText();
};

#endif // VIGENERE_H_INCLUDED

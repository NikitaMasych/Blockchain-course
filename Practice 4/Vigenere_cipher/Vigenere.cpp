#include <iostream>
#include "Vigenere.h"


void Vigenere::enterPlainText(){
    std::cout << "Enter plain text: \n";
    std::getline(std::cin, plainText);
}

void Vigenere::enterCipherText(){
    std::cout << "\n\nEnter cipher text: \n";
    std::getline(std::cin, cipherText);
}

void Vigenere::enterKey(){
    std::cout << "Enter key: \n";
    std::getline(std::cin, key);
}

std::string Vigenere::getCipherText(){
    return cipherText;
}

std::string Vigenere::getPlainText(){
    return plainText;
}

void Vigenere::encryptPlainText(){
    cipherText = "";
    size_t alphaCounter = 0; // need to ingore not alpha characters
    for (size_t i = 0; i != plainText.length(); ++i){
        char c = tolower(plainText[i]); // current character
        if (c >= 'a' && c <= 'z'){
            c = (c - 'a' + tolower(key[alphaCounter % key.length()]) - 'a' + 26) % 26 + 'a';
            // with respect to the register
            if (isupper(plainText[i])) c = toupper(c);
            alphaCounter ++;
        }
        cipherText += c;
    }
}

void Vigenere::decryptCipherText(){
     plainText = "";
     size_t alphaCounter = 0;
     for (size_t i = 0; i != cipherText.length(); ++i){
        char c = tolower(cipherText[i]); // current character
        if (c >= 'a' && c <= 'z'){
            c = (c - tolower(key[alphaCounter % key.length()]) + 26) % 26 + 'a';
            if (isupper(cipherText[i])) c = toupper(c);
            alphaCounter ++;
        }
        plainText += c;
     }
}

void Vigenere::outputCipherText(){
    std::cout << "Cipher text is: " << cipherText;
}

void Vigenere::outputPlainText(){
    std::cout << "Plain text is: " << plainText;
}

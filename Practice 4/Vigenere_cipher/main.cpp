#include "Vigenere.h"

int main()
{
    Vigenere instance;

    instance.enterPlainText();
    instance.enterKey();
    instance.encryptPlainText();
    instance.outputCipherText();

    instance.enterCipherText();
    instance.enterKey();
    instance.decryptCipherText();
    instance.outputPlainText();

    return 0;
}

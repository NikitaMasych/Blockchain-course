#include <iostream>
#include "AES.h"


int main()
{
    AES instance;

    instance.enterPlaintextAsHex();
    instance.requestKey();
    instance.encryptPlaintext();
    instance.outputCiphertext();

    //instance.decryptCiphertext();
    //instance.outputPlaintext();

    return 0;
}

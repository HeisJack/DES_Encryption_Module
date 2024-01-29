#include <iostream>
#include <string>
#include <bitset>

#include "DES_Key_Module.h"

using namespace std;

// Move the definition of hexToBinary outside the class declaration
bitset<64> DES_Key_Module::hexToBinary(const string& hexString) {
    try {
        // Convert hex string to unsigned long long
        unsigned long long hexValue = stoull(hexString, nullptr, 16);

        // Convert unsigned long long to binary using std::bitset
        return bitset<64>(hexValue);
    }
    catch (const invalid_argument& e) {
        cerr << "Error: Invalid hexadecimal string." << std::endl;
        return bitset<64>(0);
    }
}

// The rest of your implementation remains unchanged

DES_Key_Module::DES_Key_Module(const string& keyString) {
    // Convert the hexadecimal key to binary
    bitset<64> bitsetKey = hexToBinary(keyString);
    string binaryKey = bitsetKey.to_string();

    // Check if the binary key size is exactly 64 bits
    if (binaryKey.size() == 64) {
        key = binaryKey;
        cout << "Key successfully initialized." << endl;
    }
    else {
        cerr << "Error: The key size must be exactly 64 bits." << endl;
        // Optionally, you might throw an exception or handle the error in a different way.
    }
}

string DES_Key_Module::getKey() const {
    return key;
}

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
    cout << "This is the binary representation of the hexadecimal key you entered: " << endl << getKey() << endl;

    removeParityBits();

    // DEBUG
    cout << "Truncated key is: " << endl;
    for (char value : key_parity_removed) {
        cout << value;
    }
    cout << endl;
}

// Utility helper to obtain user Key
string DES_Key_Module::getKey() const {
    return key;
}

// This function takes the user key and strips the parity bits
void DES_Key_Module::removeParityBits() {
    if (key.size() != 64) {
        cerr << "Error: Key is not 64 bits in length, cannot truncate parity bits." << endl;
    }

    string truncatedKey;

    // Loop the keystring every 8 bits and removed the parity bits
    for (size_t i = 0; i < 64; i += 8) {
        string block = key.substr(i, 8);
        truncatedKey += block.substr(0, 7);  // Remove the parity bit
    }

    // Assign truncated key to the class property
    key_parity_removed = truncatedKey;
}

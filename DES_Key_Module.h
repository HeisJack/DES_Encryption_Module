// DES_Key_Module.h

#ifndef DES_KEY_MODULE_H
#define DES_KEY_MODULE_H

#include <string>
#include <bitset>

class DES_Key_Module {
private:
    std::string key;
    std::string key_parity_removed;

    std::bitset<64> hexToBinary(const std::string& hexString);

    void removeParityBits();

public:
    // Constructor that takes a string and initializes the "key" variable
    DES_Key_Module(const std::string& keyString);

    // Public function to retrieve the key value
    std::string getKey() const;
};

#endif // DES_KEY_MODULE_H

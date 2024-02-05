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

    vector<bool> converted_key = stringToBoolVector(key);

    // Perform the PC1 permutation on the key
    permutation(converted_key, PC1table, pc1_key);

    generateSubKeys(pc1_key, 16);

    cout << "All subkeys generated" << endl;
}

// Utility helper to obtain user Key
string DES_Key_Module::getKey() const {
    return key;
}

vector<vector<bool>> DES_Key_Module::getPC2Keys() const {
    return subKeys_final_pc2;
}



vector<bool> DES_Key_Module::stringToBoolVector(const string& binaryString) {
    vector<bool> boolVector;

    for (char c : binaryString) {
        if (c == '0') {
            boolVector.push_back(false);
        }
        else if (c == '1') {
            boolVector.push_back(true);
        }
        else {
            // Handle invalid characters if needed
            cerr << "Invalid character in binary string: " << c << endl;
        }
    }
    return boolVector;
}

void DES_Key_Module::permutation(vector<bool>& converted_key, const vector<int> table, vector<bool>& target) {
  
    // Get the size of the table to be used for permutation
    const size_t size = table.size();

    // Just in case, clear the target key vector of any contents that may already be there
    target.clear();
    // Resize to our current working schematic
    target.resize(size);

    // Perform the initial permutation
    for (size_t i = 0; i < size; ++i) {
        target[i] = converted_key[table[i] - 1]; // minus one to accomodate zero-indexing
    }

}

// This function will take a key and break it into tow halves, and then perform circular left
// shifts for the specified amount of iterations. The result will be stored in the
// subKeys DES_Key_Module class property
void DES_Key_Module::generateSubKeys(vector<bool>& input_key, const size_t iterations) {
    vector<bool> c;
    vector<bool> d;
    subKeys.clear();
    subKeys.resize(iterations);

    // Split key into two halves
    if (input_key.size() % 2 != 0) {
        cerr << "Error: Input vector size must be even for splitting into halves." << std::endl;
        return;
    }

    // Calculate the midpoint index
    size_t midpoint = input_key.size() / 2;
    c.assign(input_key.begin(), input_key.begin() + midpoint);
    d.assign(input_key.begin() + midpoint, input_key.end());

    vector<bool> previous_shift_c = c;
    vector<bool> previous_shift_d = d;

    // Perform the iteration over the shift table and conduct left circular shift on each half. The
    // current shifted key will be stored for the next iteration to shift against. 
    // Store shifted keys in subKeys DES_Keys_Module class property
    for (size_t i = 0; i < iterations; ++i) {
        vector<bool> left_c = circLeftShift(previous_shift_c, shiftValues[i]);
        vector<bool> right_d = circLeftShift(previous_shift_d, shiftValues[i]);

        subKeys[i].push_back(left_c);
        subKeys[i].push_back(right_d);

        previous_shift_c = left_c;
        previous_shift_d = right_d;
    }

    // Concatenate the 28-bit vectors generated in the previous step into sixteen 56-bit
    // vectors that will serve as the final subkeys
    for (size_t i = 0; i < subKeys.size(); ++i) {
        vector<bool> temp(56);
        temp.clear();
        for (size_t j = 0; j < subKeys[i].size(); ++j) {
            temp.insert(temp.end(), subKeys[i][j].begin(), subKeys[i][j].end());
            if (j == (subKeys[i].size() - 1)) {
                subKeys_final.push_back(temp);
            }
        }
    }

    // Conduct PC2 permutation against each subkey generated in previous step and store
    // in-place in subKeys_final
    subKeys_final_pc2.clear();
    vector<bool> temp(48);
    for (size_t i = 0; i < subKeys_final.size(); ++i) {
        temp.clear();
        permutation(subKeys_final[i], PC2table, temp);
        subKeys_final_pc2.push_back(temp);
    }
}

// Conduct circular left shift against provided vector
vector<bool> DES_Key_Module::circLeftShift(const vector<bool>& input, size_t shiftAmount) {
    size_t size = input.size();
    vector<bool> result(size);

    // Perform circular left shift
    for (size_t i = 0; i < size; ++i) {
        size_t shiftedIndex = (i + shiftAmount) % size;
        result[i] = input[shiftedIndex];
    }
    return result;
}



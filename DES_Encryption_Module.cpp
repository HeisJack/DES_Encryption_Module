// Lab1 - EC4770
// DES_Encryption_Module.cpp : This file contains the 'main' function. Program execution begins and ends there.
// 
// This simple DES encryption module is designed to only take binary strings from users (strings that contain only '1's and '0's)
// Entry of any sequence of characters that deviate from strictly '1's and '0's will return an error and terminate
// The program will only process a string of 64 bits in length or shorter. String longer than 64 bits will cause the program to terminate
// 
//

#include <iostream>
#include <vector>
#include <string>
#include "DES_Key_Module.h"

using namespace std;

class DES_Encryption_Module {

private:
    string userInput;
    vector<bool> message_bits;
    vector<bool> initial_permutation;
    vector<bool> r0;
    vector<bool> l0;
    DES_Key_Module keyObject;
    vector<bool> encrypted_message;
    vector<bool> decrypted_message;

    // Initial Permutation table
    const vector<int> IPtable = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    const vector<int> expansionTable = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    const int substitution_boxes[8][4][16] =
    { {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    } };

    const vector<int> PBoxPattern = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
    };

    const vector<int> FPtable = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
    };

    const vector<int> IP1table = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
    };




    vector<bool> initialPermutation(const vector<bool>& inputBlock, const vector<int> table) {
        // Check if the input block size is correct (64 bits for DES)
        if (inputBlock.size() != 64) {
            std::cerr << "Error: Incorrect block size for DES initial permutation." << endl;
            return vector<bool>();
        }

        vector<bool> permutedBlock(64);

        // Perform the initial permutation
        for (size_t i = 0; i < 64; ++i) {
            permutedBlock[i] = inputBlock[table[i] - 1];
        }

        return permutedBlock;
    }

    // Checks to make sure that input provided consists only of '1's and'0's
    int checkBinary(const string& userInput) {
        // Validate input from user to ensure binary
        if (userInput.find_first_not_of("01") != string::npos) {
            cerr << "Invalid binary string. Please enter a valid binary string." << endl;
            return 1;  // Exit with an error code
        }
    }

    // Converts the message string provided by the user to a binary vector
    vector<bool> convertToBits(string userInput) {
        // Convert 'binary' input string from user to bits
        vector<bool> bits;
        for (char c : userInput) {
            // Convert '0' and '1' characters to bits
            bits.push_back(c == '1');
        }
        return bits;
    }

    // This function will be called after the initial permutation function completes. This function splits
    // the initial permuation in to halves. The halves are stored in the l0 and r0 class properties.
    void splitPermutedMessage(vector<bool>& message) {
        if (message.size() != 64) {
            cerr << "ERROR: Initial Permutation vector is not 64 bits in length. Exiting...";
            return;
        }

        l0.clear();
        r0.clear();

        // Calculate the midpoint index
        size_t midpoint = message.size() / 2;

        // Assign the first half to the l0 class property
        l0.insert(l0.begin(), message.begin(), message.begin() + midpoint);

        // Assign the second half to the r0 class property
        r0.insert(r0.begin(), message.begin() + midpoint, message.end());
    }

    vector<bool> expansion(const vector<bool>& vector_half, const vector<int>& table) {
        vector<bool> result(48);
        size_t table_size = table.size();

        for (size_t i = 0; i < table_size; ++i) {
            result[i] = vector_half[table[i] - 1]; // minus one to accomodate zero-indexing
        }

        return result;
    }

    vector<bool> xorVectors(const vector<bool>& right_half, const vector<bool>& subKey) {
        if (right_half.size() != subKey.size()) {
            cerr << "Error: Right-half of expanded IP data and subkey must be the same size!." << endl;
            return vector<bool>();
        }

        vector<bool> result;
        result.reserve(right_half.size());

        // Perform XOR operation on corresponding bits
        for (size_t i = 0; i < right_half.size(); ++i) {
            result.push_back(right_half[i] ^ subKey[i]);
        }

        return result;
    }

    vector<bool> substitution(vector<vector<bool>> groups) {
        vector<bool> outputBits;

        for (size_t i = 0; i < groups.size(); ++i) {
            // Perform S-Box substitution for each group and append the results
            vector<bool> sBoxOutput = sBoxSubstitution(groups[i], i);
            outputBits.insert(outputBits.end(), sBoxOutput.begin(), sBoxOutput.end());
        }

        return outputBits;
    }

    vector<bool> sBoxSubstitution(const vector<bool> inputBits, int sBoxIndex) {
        vector<bool> outputBits;

        // Check if the input size is correct (should be 6 bits)
        if (inputBits.size() != 6) {
            // Handle error or return empty vector
            return outputBits;
        }

        // Determine the row and column indices for the S-Box lookup
        int row = (inputBits[0] ? 1 : 0) * 2 + (inputBits[5] ? 1 : 0);
        int col = (inputBits[1] ? 1 : 0) * 8 + (inputBits[2] ? 1 : 0) * 4 + (inputBits[3] ? 1 : 0) * 2 + (inputBits[4] ? 1 : 0);

        // Perform S-Box substitution
        int sBoxValue = substitution_boxes[sBoxIndex][row][col];

        // Convert the S-Box value to a 4-bit binary representation
        for (int i = 3; i >= 0; --i) {
            outputBits.push_back((sBoxValue >> i) & 1);
        }

        return outputBits;
    }

    vector<bool> applyPBoxPermutation(const vector<bool>& inputBits) {
        // Check if the input size is correct (should be 32 bits)
        if (inputBits.size() != 32) {
            cerr << "ERROR: provided post-Sbox substitution-phase data is not 32 bits in length!" << endl;
            return vector<bool>();
        }

        // Create a vector to store the result of the P-Box permutation
        vector<bool> outputBits(32);

        // Perform the P-Box permutation
        for (size_t i = 0; i < PBoxPattern.size(); ++i) {
            outputBits[i] = inputBits[PBoxPattern[i] - 1];
        }
        return outputBits;
    }

public:

    DES_Encryption_Module(const string userInput, const string userKey) : userInput(userInput) , keyObject(DES_Key_Module(userKey)){
        checkBinary(userInput);
        message_bits = convertToBits(userInput);
        padBits(message_bits, 64); //This should modify the class property

    }

    void padBits(vector<bool>& bits, size_t targetSize) {
        // if the bits provided are less than target size proceeed with padding
        if (bits.size() < targetSize) {
            // Number of zeroes to pad
            size_t zerosToPad = targetSize - bits.size();

            // Pad with zeros at the beginning
            bits.insert(bits.begin(), zerosToPad, false);

            cout << "Vector padded to " << targetSize << " bits: ";

            for (bool bit : bits) {
                std::cout << bit;
            }
            std::cout << std::endl;
        }
        // Return error if string is too large
        else if (bits.size() > targetSize) {
            cerr << "Length of binary string is logner than " << targetSize << " bits. Exiting program." << endl;
        }
        // String is already target size
        else {
            cout << "Binary string is already " << targetSize << " bits. No padding needed." << endl;
        }
    }

    vector<bool> getMessageBits() const {
        return message_bits;
    }

    string getMessageString() const {
        return userInput;
    }

    void encryption() {
        initial_permutation = initialPermutation(message_bits, IPtable);

        // Split the initial permuation into two vectors
        splitPermutedMessage(initial_permutation);

        vector<vector<bool>> pc2_subkeys = keyObject.getPC2Keys();

        vector<bool> right_half = r0;
        vector<bool> left_half = l0;
        vector<vector<bool>> groups;

        
        for (size_t i = 0; i < pc2_subkeys.size(); ++i) {

            vector<bool> expanded_right_half = expansion(right_half, expansionTable);

            // This is the XOR'd result of the right-half and the subkey
            vector<bool> xor_rightHalf_subkey = xorVectors(expanded_right_half, pc2_subkeys[i]);

            // The xor'ed right half is split up in to chunks of 6 bits - should result in 8 groups
            groups = splitIntoGroups(xor_rightHalf_subkey, 6);

            // The groups are then subjected to sbox substitution, each group is concatenated afterward
            vector<bool> sbox_substitutions = substitution(groups);

            // The new concatenated 32-bit vector is then permutated further use the PBox pattern
            vector<bool> pbox_permutation = applyPBoxPermutation(sbox_substitutions);

            // XOR the current left-half with the PBOX-permutated results
            vector<bool> xor_left_with_pbox = xorVectors(left_half, pbox_permutation);

            left_half = right_half;
            right_half = xor_left_with_pbox;
        }

        vector<bool> temp_left = left_half;
        vector<bool> temp_right = right_half;
        left_half = temp_right;
        right_half = temp_left;

        vector<bool> temp_final;
        temp_final.insert(temp_final.end(), left_half.begin(), left_half.end());
        temp_final.insert(temp_final.end(), right_half.begin(), right_half.end());

        encrypted_message = initialPermutation(temp_final, FPtable);

        cout << "Encrypted message: ";
        for (bool value : encrypted_message) {
            cout << value;
        }
        cout << endl;

        cout << "Encryption complete!" << endl;

    }

    vector<vector<bool>> splitIntoGroups(vector<bool> xor_vector, size_t number_of_bits) {
        if (xor_vector.size() % number_of_bits != 0) {
            cerr << "Error: Input vector length must be divisible by group size." << endl;
            return {};
        }

        vector<vector<bool>> result;
        result.reserve(xor_vector.size() / number_of_bits);

        // Split the input vector into groups
        for (size_t i = 0; i < xor_vector.size(); i += number_of_bits) {
            result.emplace_back(xor_vector.begin() + i, xor_vector.begin() + i + number_of_bits);
        }

        return result;
    }

    void decryption() {
        cout << "Decryption process starting: " << endl;
        vector<bool> inversedPermutation = initialPermutation(encrypted_message, IPtable);

        splitPermutedMessage(inversedPermutation);

        vector<vector<bool>> pc2_subkeys = keyObject.getPC2Keys();

        vector<bool> right_half = r0;
        vector<bool> expanded_right_half = expansion(r0, expansionTable);
        vector<bool> left_half = l0;
        vector<vector<bool>> groups;

        for (int i = pc2_subkeys.size() - 1; i >= 0; --i) {
            vector<bool> expanded_right_half = expansion(right_half, expansionTable);

            // This is the XOR'd result of the right-half and the subkey
            vector<bool> xor_rightHalf_subkey = xorVectors(expanded_right_half, pc2_subkeys[i]);

            // The xor'ed right half is split up in to chunks of 6 bits - should result in 8 groups
            groups = splitIntoGroups(xor_rightHalf_subkey, 6);

            // The groups are then subjected to sbox substitution, each group is concatenated afterward
            vector<bool> sbox_substitutions = substitution(groups);

            // The new concatenated 32-bit vector is then permutated further use the PBox pattern
            vector<bool> pbox_permutation = applyPBoxPermutation(sbox_substitutions);

            // XOR the current left-half with the PBOX-permutated results
            vector<bool> xor_left_with_pbox = xorVectors(left_half, pbox_permutation);

            left_half = right_half;
            right_half = xor_left_with_pbox;
        }

        vector<bool> temp_left = left_half;
        vector<bool> temp_right = right_half;
        left_half = temp_right;
        right_half = temp_left;

        vector<bool> temp_final;
        temp_final.insert(temp_final.end(), left_half.begin(), left_half.end());
        temp_final.insert(temp_final.end(), right_half.begin(), right_half.end());

        vector<bool> decrypted_message = initialPermutation(temp_final, IP1table);

        //decrypted_message = initialPermutation(decrypted_message_pre_inverse, IP1table);

        cout << "Decrypted Message: " << endl;
        for (bool value : decrypted_message) {
            cout << value;
        }
        cout << endl;

    }

};

int main()
{
    // Get binary string from user to be encrypted
    string userInput;
    cout << "Enter a binary string: ";
    cin >> userInput;

    // Get hexadecimal 64-bit key from user
    string userKey;
    cout << "Enter a 64-bit hexadecimal key string: ";
    cin >> userKey;

    DES_Encryption_Module des(userInput, userKey);

    des.encryption();

    des.decryption();

    system("pause");
    // Wait for user input before closing the console window
    cout << "Press Enter to exit.";
    cin.get();

    return 0;
}


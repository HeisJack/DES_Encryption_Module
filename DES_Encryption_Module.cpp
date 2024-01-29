// Lab1 - EC4770 - John Sibert
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

    vector<bool> initialPermutation(const vector<bool>& inputBlock) {
        // Check if the input block size is correct (64 bits for DES)
        if (inputBlock.size() != 64) {
            std::cerr << "Error: Incorrect block size for DES initial permutation." << endl;
            return vector<bool>();
        }

        vector<bool> permutedBlock(64);

        // Perform the initial permutation
        for (size_t i = 0; i < 64; ++i) {
            permutedBlock[i] = inputBlock[IPtable[i] - 1];
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
    void splitPermutedMessage() {
        if (initial_permutation.size() != 64) {
            cerr << "ERROR: Initial Permutation vector is not 64 bits in length. Exiting...";
            return;
        }

        l0.clear();
        r0.clear();

        // Calculate the midpoint index
        size_t midpoint = initial_permutation.size() / 2;

        // Assign the first half to the l0 class property
        l0.insert(l0.begin(), initial_permutation.begin(), initial_permutation.begin() + midpoint);

        // Assign the second half to the r0 class property
        r0.insert(r0.begin(), initial_permutation.begin() + midpoint, initial_permutation.end());
    }

public:

    DES_Encryption_Module(const string userInput, const string userKey) : userInput(userInput){
        checkBinary(userInput);
        message_bits = convertToBits(userInput);
        padBits(message_bits, 64); //This should modify the class property

        // Begin Key initialization process
        DES_Key_Module keyModule(userKey);
        cout << "This is the binary representation of the hexadecimal key you entered: " << endl << keyModule.getKey() << endl;
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
        initial_permutation = initialPermutation(message_bits);

        // Print the vector elements
        cout << " Permuted Bit Vector: ";
        for (bool value : initial_permutation) {
            cout << value;
        }
        cout << endl;

        // Split the initial permuation into two vectors
        splitPermutedMessage();

        // For testing purposes only. Print l0
        cout << "This is the contents of l0" << endl;
        for (bool value : l0) {
            cout << value;
        }
        cout << endl;

        // For testing purposes only. Print r0
        cout << "This is the contents of r0" << endl;
        for (bool value : r0) {
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

    return 0;
}


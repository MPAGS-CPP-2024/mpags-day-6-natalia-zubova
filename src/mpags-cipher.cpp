#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "Exceptions.hpp"
#include "ProcessCommandLine.hpp"
#include "TransformChar.hpp"

#include <algorithm>
#include <fstream>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char* argv[])
{
    // Convert the command-line arguments into a more easily usable form
    const std::vector<std::string> cmdLineArgs{argv, argv + argc};

    // Options that might be set by the command-line arguments
    ProgramSettings settings{false, false, "", "", {}, {}, CipherMode::Encrypt};

    // Process command line arguments
    try {
        processCommandLine(cmdLineArgs, settings);
    } catch (const MissingArgument& e) {
        std::cerr << "[error] Missing argument: " << e.what() << std::endl;
        return 1;
    }

    // Handle help, if requested
    if (settings.helpRequested) {
        // Line splitting for readability
        std::cout
            << "Usage: mpags-cipher [-h/--help] [--version] [-i <file>] [-o <file>] [-c <cipher>] [-k <key>] [--encrypt/--decrypt]\n\n"
            << "Encrypts/Decrypts input alphanumeric text using classical ciphers\n\n"
            << "Available options:\n\n"
            << "  -h|--help        Print this help message and exit\n\n"
            << "  --version        Print version information\n\n"
            << "  -i FILE          Read text to be processed from FILE\n"
            << "                   Stdin will be used if not supplied\n\n"
            << "  -o FILE          Write processed text to FILE\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "                   Stdout will be used if not supplied\n\n"
            << "  --multi-cipher N Specify the number of ciphers to be used in sequence\n"
            << "                   N should be a positive integer - defaults to 1"
            << "  -c CIPHER        Specify the cipher to be used to perform the encryption/decryption\n"
            << "                   CIPHER can be caesar, playfair, or vigenere - caesar is the default\n\n"
            << "  -k KEY           Specify the cipher KEY\n"
            << "                   A null key, i.e. no encryption, is used if not supplied\n\n"
            << "  --encrypt        Will use the cipher to encrypt the input text (default behaviour)\n\n"
            << "  --decrypt        Will use the cipher to decrypt the input text\n\n"
            << std::endl;
        // Help requires no further action, so return from main
        // with 0 used to indicate success
        return 0;
    }

    // Handle version, if requested
    // Like help, requires no further action,
    // so return from main with zero to indicate success
    if (settings.versionRequested) {
        std::cout << "0.5.0" << std::endl;
        return 0;
    }

    // Initialise variables
    char inputChar{'x'};
    std::string cipherText;

    // Read in user input from stdin/file
    if (!settings.inputFile.empty()) {
        // Open the file and check that we can read from it
        std::ifstream inputStream{settings.inputFile};
        if (!inputStream.good()) {
            std::cerr << "[error] failed to create istream on file '"
                      << settings.inputFile << "'" << std::endl;
            return 1;
        }

        // Loop over each character from the file
        while (inputStream >> inputChar) {
            cipherText += transformChar(inputChar);
        }

    } else {
        // Loop over each character from user input
        // (until Return then CTRL-D (EOF) pressed)
        while (std::cin >> inputChar) {
            cipherText += transformChar(inputChar);
        }
    }

    // Request construction of the appropriate cipher(s)
    std::vector<std::unique_ptr<Cipher>> ciphers;
    std::size_t nCiphers{settings.cipherType.size()};
    ciphers.reserve(nCiphers);
    for (std::size_t iCipher{0}; iCipher < nCiphers; ++iCipher) {
        ciphers.push_back(CipherFactory::makeCipher(
            settings.cipherType[iCipher], settings.cipherKey[iCipher]));

        // Check that the cipher was constructed successfully
        if (!ciphers.back()) {
            std::cerr << "[error] problem constructing requested cipher"
                      << std::endl;
            return 1;
        }
    }

    // If we are decrypting, we need to reverse the order of application of the ciphers
    if (settings.cipherMode == CipherMode::Decrypt) {
        std::reverse(ciphers.begin(), ciphers.end());
    }
    // Run the cipher(s) on the input text, specifying whether to encrypt/decrypt
    // and using multithreading
    std::vector<std::future<std::string>>
        futures;    // Vector to hold futures for each thread
    std::vector<std::string> substrings;    // To store substrings for threads

    // Divide the input text into parts based on the number of threads
    std::size_t numThreads = 4;
    size_t length = cipherText.size();
    size_t partSize = length / numThreads;

    // Start a thread for each substring
    for (size_t i = 0; i < numThreads; ++i) {
        std::size_t start = partSize * i;
        std::size_t currentPartSize =
            start + partSize > length ? length - start : partSize;
        futures.push_back(std::async(
            std::launch::async,
            [&ciphers, &settings](const std::string& text) -> std::string {
                std::string result = text;
                for (const auto& cipher : ciphers) {
                    result = cipher->applyCipher(result, settings.cipherMode);
                }
                return result;
            },
            cipherText.substr(
                start, currentPartSize)    // Pass the substring for this thread
            ));
    }

    // Wait for all threads to finish and gather the results
    std::string finalResult;
    for (auto& future : futures) {
        finalResult += future.get();    // Combine results from all threads
    }

    cipherText = finalResult;    // Set the final result back to cipherText

    // Output the encrypted/decrypted text to stdout/file
    if (!settings.outputFile.empty()) {
        // Open the file and check that we can write to it
        std::ofstream outputStream{settings.outputFile};
        if (!outputStream.good()) {
            std::cerr << "[error] failed to create ostream on file '"
                      << settings.outputFile << "'" << std::endl;
            return 1;
        }

        // Print the encrypted/decrypted text to the file
        outputStream << cipherText << std::endl;

    } else {
        // Print the encrypted/decrypted text to the screen
        std::cout << cipherText << std::endl;
    }

    // No requirement to return from main, but we do so for clarity
    // and for consistency with other functions
    return 0;
}

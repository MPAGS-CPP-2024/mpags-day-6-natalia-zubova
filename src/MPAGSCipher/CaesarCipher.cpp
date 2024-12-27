#include "CaesarCipher.hpp"
#include "Alphabet.hpp"
#include "Exceptions.hpp"

#include <iostream>
#include <string>

CaesarCipher::CaesarCipher(const std::size_t key) : key_{key % Alphabet::size}
{
}

CaesarCipher::CaesarCipher(const std::string& key) : key_{0}
{
    // We have the key as a string, but the Caesar cipher needs an unsigned long, so we first need to convert it
    if (key.empty()) {
        throw InvalidKey("Empty key");
    }
    try{
        key_ = std::stoul(key) % Alphabet::size;
    }
    catch (const std::invalid_argument&){
        throw InvalidKey("Invalid key: " + key);
    }
    catch (const std::out_of_range&){
        throw InvalidKey("Invalid key: " + key);
    }
}

std::string CaesarCipher::applyCipher(const std::string& inputText,
                                      const CipherMode cipherMode) const
{
    // Create the output string
    std::string outputText;

    // Loop over the input text
    char processedChar{'x'};
    for (const auto& origChar : inputText) {
        // For each character in the input text, find the corresponding position in
        // the alphabet by using an indexed loop over the alphabet container
        for (std::size_t i{0}; i < Alphabet::size; ++i) {
            if (origChar == Alphabet::alphabet[i]) {
                // Apply the appropriate shift (depending on whether we're encrypting
                // or decrypting) and determine the new character
                // Can then break out of the loop over the alphabet
                switch (cipherMode) {
                    case CipherMode::Encrypt:
                        processedChar =
                            Alphabet::alphabet[(i + key_) % Alphabet::size];
                        break;
                    case CipherMode::Decrypt:
                        processedChar =
                            Alphabet::alphabet[(i + Alphabet::size - key_) %
                                               Alphabet::size];
                        break;
                }
                break;
            }
        }

        // Add the new character to the output text
        outputText += processedChar;
    }

    return outputText;
}
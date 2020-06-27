#pragma once

#include <string>

#include "hamarr.hpp"

namespace set_02::challenge_12
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 2 : Challenge 12 ]  \n");

  // Pretend we don't know what this key is!
  auto key = hmr::hex::decode("56 EB 4C 11 A2 1B 38 D9 E3 53 E0 28 CE 12 53 D1");

  // Decode and append this to the plaintext before encrypting
  auto appended = hmr::base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

  // Lambda to append the mystery text and encrypt
  auto encrypt = [&appended](const std::string &input, std::string_view key) -> std::string
  {
    auto plaintext = input + appended;
    auto ciphertext = hmr::crypto::aes_ecb_encrypt(plaintext, key);

    return ciphertext;
  };

  // Lambda to discover the block size of the cipher
  [[maybe_unused]]
  auto discover_block_size = []() -> std::size_t
  {
    return 0;
  };


  auto result = encrypt("A", key);

  LOG_INFO(hmr::hex::encode(result));
}

} // namespace set_02::challenge_12
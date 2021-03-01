#include "set_02/all_challenges.hpp"

#include <string>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/base64.hpp>
#include <hamarr/crypto.hpp>
#include <hamarr/prng.hpp>
#include <hamarr/analysis.hpp>
#include <hamarr/pkcs7.hpp>

namespace set_02
{

////////////////////////////////////////////////
void challenge_12()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 12 ]  \n");

  // Generate a random key
  auto key = hmr::prng::bytes(16);

  // Decode and append the following mystery text to any plaintext before encrypting
  auto mystery_text = hmr::base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

  // Lambda to append the mystery text and encrypt using our random key
  auto encrypt = [&mystery_text](const std::string &input, std::string_view key) -> std::string {
    auto plaintext = input + mystery_text;
    auto ciphertext = hmr::crypto::aes_ecb_encrypt(plaintext, key);

    return ciphertext;
  };

  // Pretend we don't know anything about the mystery text
  // We can determine its length (to the nearest block size) by encrypting an empty message
  auto empty_test = encrypt("", key);
  std::size_t mystery_text_size = empty_test.size();
  spdlog::info("Mystery text size (to nearest block): {}", mystery_text_size);


  // 1. Discover the block size of the cipher. You know it, but do this step anyway.

  // Lambda to discover the block size of the cipher
  auto discover_block_size = [&encrypt](std::string const &key) -> std::size_t {
    // Keep increasing size of input until size of output changes
    auto plaintext = std::string{"A"};
    auto ciphertext = encrypt(plaintext, key);
    std::size_t prev_size = ciphertext.size();

    // Try block sizes up to 64
    for (std::size_t i = 0; i < 64; ++i)
    {
      plaintext += "A";
      ciphertext = encrypt(plaintext, key);
      std::size_t this_size = ciphertext.size();

      if (this_size > prev_size)
      {
        std::size_t const block_size = this_size - prev_size;
        return block_size;
      }
    }

    spdlog::warn("Couldn't find block size!");

    return 0;
  };

  std::size_t block_size = discover_block_size(key);
  spdlog::info("Discovered block size: {}", block_size);

  // 2. Detect that the function is using ECB. You already know, but do this step anyways.
  auto long_plaintext = std::string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}; // 48 identical chars, so if we're dealing with 16 byte blocks in ECB mode we are guaranteed to get at least 2 repeated ciphertext blocks
  auto long_ciphertext = encrypt(long_plaintext, key);

  bool is_ecb = hmr::analysis::repeated_blocks(long_ciphertext);

  if (is_ecb)
  {
    spdlog::info("Yup, it's ECB alright!");
  } else
  {
    spdlog::warn("Nope, doesn't look like ECB...");
  }

  auto reconstructed = std::string{}; // We'll use this to reconstruct the mystery text, one byte at a time
  reconstructed.reserve(mystery_text_size);

  // We know we have mystery_text_size worth of bytes to uncover
  for (std::size_t i = 0; i < mystery_text_size; ++i)
  {
    // The length of our input prefix will have to shrink each time, in order that the next unknown char of the mystery text is at the end of the block
    std::size_t const length_of_prefix = (block_size - (1 + reconstructed.size())) % block_size;

    auto const prefix = std::string(length_of_prefix, 'A');
    auto const real_ciphertext = encrypt(prefix, key);

    // The length of the ciphertext that we need to compare will increase as we reconstruct more of the mystery text
    std::size_t const length_to_compare = length_of_prefix + reconstructed.size() + 1;

    // This shouldn't happen, but just in case we got our maths wrong...
    if (length_to_compare > real_ciphertext.size())
    {
      spdlog::warn("Comparison length is too large!!");
      return;
    }

    auto const real_chunk = real_ciphertext.substr(0, length_to_compare);

    // Try each possible final character
    for (std::size_t i = 0; i < 256; ++i)
    {
      // Build the prefix for this test run
      auto const test_prefix = prefix + reconstructed + static_cast<char>(i);

      // Try encrypting
      auto const test_ciphertext = encrypt(test_prefix, key);

      // Compare the first length_of_prefix+reconstructed.size()+1 bytes
      auto const test_chunk = test_ciphertext.substr(0, length_to_compare);

      // Did this prefix produce ciphertext that matches the real ciphertext?
      // If so, we've found the next char of the mystery text, so can stop the loop!
      if (test_chunk == real_chunk)
      {
        uint8_t const final_char = static_cast<uint8_t>(i);
        reconstructed.push_back(final_char);
        break;
      }
    }
  }

  // Remove any padding
  reconstructed = hmr::pkcs7::unpad(reconstructed);

  // Finally, check the reconstructed text against the original mystery text
  if (reconstructed == mystery_text)
  {
    spdlog::info("Output :\n\n{}", reconstructed);
  } else
  {
    spdlog::warn("Reconstructed text doesn't match original mystery text...");
  }
}

} // namespace set_02

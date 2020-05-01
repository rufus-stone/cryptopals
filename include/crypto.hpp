#pragma once

#include <cassert>

#include <string_view>
#include <string>
#include <vector>

#include <type_traits>

#include <openssl/aes.h>

#include "utils.hpp"

using namespace std::string_literals;

namespace cp
{

// Forward declarations
std::string zero_pad(const std::string &input, std::size_t block_size = 16);

std::string aes_ecb_encrypt_block(std::string_view input, std::string_view key);
std::string aes_ecb_decrypt_block(std::string_view input, std::string_view key);

std::string aes_ecb_encrypt(std::string_view input, std::string_view key);
std::string aes_ecb_decrypt(std::string_view input, std::string_view key, bool remove_padding = true);

std::string aes_cbc_encrypt(std::string_view input, std::string_view key, const std::string &iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s);
std::string aes_cbc_decrypt(std::string_view input, std::string_view key, const std::string &iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s, bool remove_padding = true);


std::string zero_pad(const std::string &input, std::size_t block_size)
{
  uint8_t padding_required = input.size() % block_size;

  if (padding_required == 0)
  {
    return input;
  }

  padding_required = block_size - padding_required;

  std::string output;
  output.reserve(input.size() + padding_required);

  output = input;

  for (std::size_t n = 0; n < padding_required; ++n)
  {
    output.push_back(0x00);
  }
  
  return output;
}

////////////////////////////////////////////////////////////////
std::string aes_ecb_encrypt_block(std::string_view input, std::string_view key)
{
  // AES-128 keys and blocks must be 16 bytes long
  assert(input.size() == 16);
  assert(key.size() == 16);

  auto plaintext_ptr = reinterpret_cast<const uint8_t *>(input.data());
  auto key_ptr = reinterpret_cast<const uint8_t *>(key.data());

  auto encrypted = std::vector<uint8_t>(input.size(), 0x00); // We have to initialise the vector with something to start with

  AES_KEY aes_key;
  AES_set_encrypt_key(key_ptr, 128, &aes_key);

  AES_encrypt(plaintext_ptr, encrypted.data(), &aes_key);

  auto result = std::string{};
  result.reserve(encrypted.size());

  std::copy(std::begin(encrypted), std::end(encrypted), std::back_inserter(result));

  return result;
}

////////////////////////////////////////////////////////////////
std::string aes_ecb_decrypt_block(std::string_view input, std::string_view key)
{
  // AES-128 keys and blocks must be 16 bytes long
  assert(input.size() == 16);
  assert(key.size() == 16);

  auto ciphertext_ptr = reinterpret_cast<const uint8_t *>(input.data());
  auto key_ptr = reinterpret_cast<const uint8_t *>(key.data());

  auto decrypted = std::vector<uint8_t>(input.size(), 0x00); // We have to initialise the vector with something to start with

  AES_KEY aes_key;
  AES_set_decrypt_key(key_ptr, 128, &aes_key);

  AES_decrypt(ciphertext_ptr, decrypted.data(), &aes_key);

  auto result = std::string{};
  result.reserve(decrypted.size());

  std::copy(std::begin(decrypted), std::end(decrypted), std::back_inserter(result));

  return result;
}

////////////////////////////////////////////////////////////////
std::string aes_ecb_encrypt(std::string_view input, std::string_view key)
{
  // Will the input need padding? Make sure we account for this when initialising the output vector
  int len = input.size();
  int padding = ((len % 16) == 0) ? 0 : 16 - (len % 16);

  auto result = std::string{};

  LOG_INFO("AES encrypting " << len << " bytes (padded to " << len + padding << ") in ECB mode using key: " << hmr::hex::encode(key));

  // How many complete blocks are there
  auto num_blocks = len / 16;

  // Encrypt all the complete blocks first
  std::size_t offset;
  for (offset = 0; offset < (num_blocks * 16); offset += 16)
  {
    auto encrypted_block = aes_ecb_encrypt_block(input.substr(offset, 16), key);
    result += encrypted_block;
  }

  // If the input wasn't a multiple of 16 bytes, there will be a final block that needs padding before it can be encrypted
  if (len % 16 != 0)
  {
    auto final_block = hmr::pkcs7::pad(std::string(input.data() + offset, len - offset));
    auto encrypted_block = aes_ecb_encrypt_block(final_block, key);
    result += encrypted_block;
  }

  // Abort condition
  if (result.empty())
  {
    LOG_INFO("Failed to encrypt any data!");
    return std::string{};
  }

  return result;
}

////////////////////////////////////////////////////////////////
std::string aes_ecb_decrypt(std::string_view input, std::string_view key, bool remove_padding)
{
  int len = input.size();

  // AES encrypted data should a multiple of 16 bytes
  assert(len % 16 == 0);

  auto result = std::string{};

  LOG_INFO("AES decrypting " << len << " bytes in ECB mode using key: " << hmr::hex::encode(key));

  // How many blocks are there
  auto num_blocks = len / 16;
  std::size_t current_block = 1;

  // Decrypt all the blocks
  for (std::size_t offset = 0; offset < len; offset += 16, ++current_block)
  {
    auto decrypted_block = aes_ecb_decrypt_block(input.substr(offset, 16), key);
    
    // If this was the last block, check whether we need to remove padding
    if (current_block == num_blocks)
    {
      if (remove_padding)
      {
        result += hmr::pkcs7::unpad(decrypted_block);
      } else
      {
        result += decrypted_block;
      }
    } else
    {
      result += decrypted_block;
    }
  }

  // Abort condition
  if (result.empty())
  {
    LOG_INFO("Failed to decrypt any data!");
    return std::string{};
  }

  return result;
}

////////////////////////////////////////////////////////////////
std::string aes_cbc_encrypt(std::string_view input, std::string_view key, const std::string &iv)
{
  // AES-128 keys and IVs must be 16 bytes long
  assert(key.size() == 16);
  assert(iv.size() == 16);

  // Will the input need padding? Make sure we account for this when initialising the output vector
  int len = input.size();
  int padding = ((len % 16) == 0) ? 0 : 16 - (len % 16);

  auto result = std::string{};
  result.reserve(len + padding);

  LOG_INFO("AES encrypting " << len << " bytes (padded to " << len + padding << ") in CBC mode using key: " << hmr::hex::encode(key) << " and IV: " << hmr::hex::encode(iv));

  // How many complete blocks are there
  auto num_blocks = len / 16;

  // In CBC mode, each block of ciphertext is XORed against the next block of plaintext before that plaintext is encrypted. The IV is used as a fake block of ciphertext to kick things off
  auto previous_ciphertext = iv;

  // Encrypt all the complete blocks first
  std::size_t offset;
  for (offset = 0; offset < (num_blocks * 16); offset += 16)
  {
    // XOR the plaintext against the previous ciphertext
    auto xord = hmr::bitwise::xor_with_key(input.substr(offset, 16), previous_ciphertext);
    auto encrypted_block = aes_ecb_encrypt_block(xord, key);

    previous_ciphertext = encrypted_block;

    result += encrypted_block;
  }

  // If the input wasn't a multiple of 16 bytes, there will be a final block that needs padding before it can be encrypted
  if (len % 16 != 0)
  {
    auto final_block = hmr::pkcs7::pad(std::string(input.data() + offset, len - offset));
    auto xord = hmr::bitwise::xor_with_key(final_block, previous_ciphertext);
    auto encrypted_block = aes_ecb_encrypt_block(xord, key);

    result += encrypted_block;
  }

  return result;
}

////////////////////////////////////////////////////////////////
std::string aes_cbc_decrypt(std::string_view input, std::string_view key, const std::string &iv, bool remove_padding)
{
  return std::string{};
}


} // namespace cp

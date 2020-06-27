#pragma once

#include <string>

#include <cassert>

#include "downloader.hpp"
#include "crypto.hpp"

#include "utils.hpp"

namespace set_02::challenge_10
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 2 : Challenge 10 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/10.txt", 2, 10);

  auto data = cp::file_to_string(file_path);

  auto decoded = hmr::base64::decode(data);

  if (decoded.empty())
  {
    LOG_ERROR("Failed to base64 decode data!");
  }

  // Let's work with a string view, for more efficient sub-string creation
  auto data_view = std::string_view{decoded};
  
  // Let's test out the ECB encryption/decryption
  auto ecb_ciphertext = hmr::hex::decode("5f68aedde83f2da44311978e1114cb9be708fdb912ea9bdc7efc9a0eeb6bcec808bfdc8c7df07eb748bce24a6bcad6e8254113c412e3cca33848cdfa81170348");
  auto plaintext = std::string{"This is a really banging test string, whatwhaaaaaaat!"};
  auto key = std::string{"YELLOW SUBMARINE"};

  assert(cp::aes_ecb_decrypt(ecb_ciphertext, key) == plaintext);
  assert(cp::aes_ecb_encrypt(plaintext, key) == ecb_ciphertext);

  // Now try CBC mode
  auto cbc_ciphertext = hmr::hex::decode("5f68aedde83f2da44311978e1114cb9bbd66daf644691a3786c6a857135a454e720a971d5450cff3f0271048d29f73fe2c27113948368ace3375d1b8b77de590");
  auto iv = std::string{"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s};

  assert(cp::aes_cbc_decrypt(cbc_ciphertext, key, iv) == plaintext);
  assert(cp::aes_cbc_encrypt(plaintext, key, iv) == cbc_ciphertext);

  LOG_INFO("\nAES ECB and CBC checks passed.\n");

  // Now that we know ECB and CBC mode are both working fine, let's decrypt the challenge data
  auto result = cp::aes_cbc_decrypt(data_view, key, iv);

  LOG_INFO(result);
}

} // namespace set_02::challenge_10
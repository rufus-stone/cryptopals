#pragma once

#include <string>

#include <cassert>

#include "downloader.hpp"
#include "crypto.hpp"

#include "utils.hpp"

namespace set_02::challenge_10
{

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
  const std::size_t len = data_view.size();
  
  // Let's test out the ECB encryption/decryption
  auto ciphertext = hmr::hex::decode("5f68aedde83f2da44311978e1114cb9be708fdb912ea9bdc7efc9a0eeb6bcec808bfdc8c7df07eb748bce24a6bcad6e8254113c412e3cca33848cdfa81170348");
  auto plaintext = std::string{"This is a really banging test string, whatwhaaaaaaat!"};
  auto key = std::string{"YELLOW SUBMARINE"};

  assert(cp::aes_ecb_decrypt(ciphertext, key) == plaintext);
  assert(cp::aes_ecb_encrypt(plaintext, key) == ciphertext);

  // Now try CBC mode
  ciphertext = cp::aes_cbc_encrypt(plaintext, key);
  LOG_INFO(hmr::hex::encode(ciphertext));
}

} // namespace set_02::challenge_10
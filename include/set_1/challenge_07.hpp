#pragma once

#include <cassert>

#include <openssl/aes.h>

#include "downloader.hpp"
#include "crypto.hpp"

namespace set_01::challenge_07
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 7 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/7.txt", 1, 7);
  
  auto data = cp::file_to_string(file_path);

  auto decoded = hmr::base64::decode(data);
  auto data_view = std::string_view{decoded};

  // The data has been encrypted via AES-128 in ECB mode under the key: YELLOW SUBMARINE
  auto decrypted = cp::aes_ecb_decrypt(data_view, "YELLOW SUBMARINE");

  if (!decrypted.empty())
  {
    LOG_INFO(decrypted);
  }

}

} // namespace set_01::challenge_07

#pragma once

#include <cassert>

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace set_01::challenge_07
{

auto aes_ecb_decrypt(std::string_view input, std::string_view key)
{
  int len = input.size();
  assert(len % 16 == 0);

  assert(key.size() == 16);

  auto ciphertext_ptr = reinterpret_cast<const uint8_t *>(input.data());
  auto key_ptr = reinterpret_cast<const uint8_t *>(key.data());

  auto output = std::vector<uint8_t>(len, 0x00); // We have to initialise the vector with something to start with

  LOG_INFO("AES decrypting in ECB mode using key: " << hmr::hex::encode(key));

  AES_KEY aes_key;
  AES_set_decrypt_key(key_ptr, 128, &aes_key);

  for (std::size_t offset = 0; offset < len; offset += 16)
  {
    AES_decrypt(ciphertext_ptr+offset, output.data()+offset, &aes_key);
  }

  LOG_INFO(output.size());

  return output;
}

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 7 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/7.txt", 1, 7);
  
  auto data = cp::file_to_string(file_path);

  auto decoded = hmr::base64::decode(data);
  auto data_view = std::string_view{decoded};

  // The data has been encrypted via AES-128 in ECB mode under the key: YELLOW SUBMARINE
  auto decrypted = aes_ecb_decrypt(data_view, "YELLOW SUBMARINE");

  if (!decrypted.empty())
  {
    auto result = std::string{};
    std::copy(std::begin(decrypted), std::end(decrypted), std::back_inserter(result));

    LOG_INFO(result);
  }

}

} // namespace set_01::challenge_07

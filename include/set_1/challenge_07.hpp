#pragma once

#include <cassert>

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace set_01::challenge_07
{

auto aes_ecb_decrypt(std::string_view input, std::string_view key)
{
  int len = input.size();

  assert(key.size() == 16);

  auto ciphertext_ptr = reinterpret_cast<const uint8_t *>(input.data());
  auto key_ptr = reinterpret_cast<const uint8_t *>(key.data());

  auto output = std::vector<uint8_t>(len, 0x00);

  LOG_INFO("AES decrypting in ECB mode using key: " << hmr::hex::encode(key));

  AES_KEY aes_key;
  AES_set_decrypt_key(key_ptr, 128, &aes_key);
  AES_decrypt(ciphertext_ptr, output.data(), &aes_key);
  AES_decrypt(ciphertext_ptr+16, output.data()+16, &aes_key); // Need to loop through all the blocks

  LOG_INFO(output.size());

  return output;
}

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 7 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/7.txt", 1, 7);

  if (!std::filesystem::exists(file_path))
  {
    LOG_ERROR("Failed to get data for Set 1 : Challenge 7!");
    return;
  }

  // Open the file
  auto file_in = std::ifstream{file_path, std::ios::binary};

  // Read in a line at a time
  auto line = std::string{};
  auto data = std::string{};
  while (std::getline(file_in, line))
  {
    data += line;
  }

  // Close the file if necessary - not sure this is needed...
  if (file_in.is_open())
  {
    file_in.close();
  }

  // Abort condition - did we read any lines?
  if (data.empty())
  {
    LOG_ERROR("Failed to read any data from file!");
    return;
  }

  auto decoded = hmr::base64::decode(data);
  auto data_view = std::string_view{decoded};

  // The data has been encrypted via AES-128 in ECB mode under the key: YELLOW SUBMARINE
  auto decrypted = aes_ecb_decrypt(data_view, "YELLOW SUBMARINE");

  if (!decrypted.empty())
  {
    LOG_INFO("Something happened!");
    auto result = std::string{};

    std::copy(std::begin(decrypted), std::end(decrypted), std::back_inserter(result));

    LOG_INFO(result);
  }

}

} // namespace set_01::challenge_07

#pragma once

#include <cassert>

#include <openssl/evp.h>

namespace set_01::challenge_07
{

auto aes_ecb_decrypt(std::string_view input, std::string_view key)
{
  int len = input.size();

  assert(key.size() == 16);

  auto ciphertext_ptr = reinterpret_cast<const uint8_t *>(input.data());
  auto key_ptr = reinterpret_cast<const uint8_t *>(key.data());

  auto output = std::vector<uint8_t>{};
  output.reserve(len);

  LOG_INFO("AES decrypting in ECB mode using key: " << hmr::hex::encode(key));

  auto ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key_ptr, nullptr);

  int outlen;
  EVP_DecryptUpdate(ctx, output.data(), &outlen, ciphertext_ptr, len);
  LOG_INFO("outlen: " << outlen);
  EVP_DecryptFinal_ex(ctx, output.data() + outlen, &outlen);
  LOG_INFO("outlen: " << outlen);

  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);

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
  }

}

} // namespace set_01::challenge_07

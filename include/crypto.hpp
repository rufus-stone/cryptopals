#pragma once

#include <cassert>

#include <string_view>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

#include <hamarr/prng.hpp>
#include <hamarr/crypto.hpp>
#include <hamarr/hex.hpp>

namespace cp
{

std::string encrypt_under_random_key_and_mode(const std::string &input)
{
  // Generate a random key, and randomly choose between ECB and CBC mode
  auto key = hmr::prng::bytes(16);
  auto coin_toss = hmr::prng::number_between<uint8_t>(0, 1);

  // Generate between 5 and 10 random bytes to prepend to the start of the plaintext, and another 5 - 10 random bytes to append at the end
  auto bytes_to_prepend = hmr::prng::bytes(hmr::prng::number_between<std::size_t>(5, 10));
  auto bytes_to_append = hmr::prng::bytes(hmr::prng::number_between<std::size_t>(5, 10));

  spdlog::info("key:  {}", hmr::hex::encode(key));
  spdlog::info("prep: {}", hmr::hex::encode(bytes_to_prepend));
  spdlog::info("app:  {}", hmr::hex::encode(bytes_to_append));

  auto modified_input = bytes_to_prepend + input + bytes_to_append;

  // Will the input need padding? Make sure we account for this when initialising the output vector
  const std::size_t len = modified_input.size();
  const std::size_t padding = ((len % 16) == 0) ? 0 : 16 - (len % 16);

  // Which mode are we using? 0 == ECB, 1 == CBC
  switch (coin_toss)
  {
    case 0:
    {
      spdlog::info("AES encrypting {} bytes (padded to {}) in ECB mode.", len, len + padding);

      return hmr::crypto::aes_ecb_encrypt(modified_input, key);
    }

    case 1:
    {
      // Generate a random IV
      auto iv = hmr::prng::bytes(16);
      spdlog::info("iv:   {}", hmr::hex::encode(iv));
      spdlog::info("AES encrypting {} bytes (padded to {}) in CBC mode.", len, len + padding);

      return hmr::crypto::aes_cbc_encrypt(modified_input, key, iv);
    }

    default:
      spdlog::info("This shouldn't happen!");
      return std::string{};
  }
}


} // namespace cp

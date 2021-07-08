#include "set_02/all_challenges.hpp"

#include <string>
#include <cassert>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/base64.hpp>
#include <hamarr/crypto.hpp>

#include "utils/downloader.hpp"
#include "utils/crypto.hpp"

namespace set_02
{

using namespace std::string_literals;

////////////////////////////////////////////////
void challenge_10()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 10 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/10.txt", 2, 10);

  std::string const data = cp::file_to_string(file_path);

  std::string const decoded = hmr::base64::decode(data);

  if (decoded.empty())
  {
    spdlog::error("Failed to base64 decode data!");
  }

  // Let's work with a string view, for more efficient sub-string creation
  auto data_view = std::string_view{decoded};

  // Let's test out the ECB encryption/decryption
  std::string const ecb_ciphertext = hmr::hex::decode("5f68aedde83f2da44311978e1114cb9be708fdb912ea9bdc7efc9a0eeb6bcec808bfdc8c7df07eb748bce24a6bcad6e8254113c412e3cca33848cdfa81170348");
  std::string const plaintext = "This is a really banging test string, whatwhaaaaaaat!"s;
  std::string const key = "YELLOW SUBMARINE"s;

  assert(hmr::crypto::aes_ecb_decrypt(ecb_ciphertext, key) == plaintext);
  assert(hmr::crypto::aes_ecb_encrypt(plaintext, key) == ecb_ciphertext);

  // Now try CBC mode
  std::string const cbc_ciphertext = hmr::hex::decode("5f68aedde83f2da44311978e1114cb9bbd66daf644691a3786c6a857135a454e720a971d5450cff3f0271048d29f73fe2c27113948368ace3375d1b8b77de590");
  std::string const iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s;

  assert(hmr::crypto::aes_cbc_decrypt(cbc_ciphertext, key, iv) == plaintext);
  assert(hmr::crypto::aes_cbc_encrypt(plaintext, key, iv) == cbc_ciphertext);

  spdlog::info("AES ECB and CBC checks passed.");

  // Now that we know ECB and CBC mode are both working fine, let's decrypt the challenge data
  std::string const result = hmr::crypto::aes_cbc_decrypt(data_view, key, iv);

  spdlog::info("Output :\n\n{}", result);
}

} // namespace set_02

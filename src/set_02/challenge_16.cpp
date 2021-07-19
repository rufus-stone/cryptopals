#include "set_02/all_challenges.hpp"

#include <hamarr/hex.hpp>
#include <string>
#include <string_view>
#include <regex>

#include <spdlog/spdlog.h>

#include <hamarr/pkcs7.hpp>
#include <hamarr/crypto.hpp>
#include <hamarr/prng.hpp>

namespace set_02
{

using namespace std::string_literals;

static const auto rgx = std::regex{R"([^;=]+)"};

// Lambda to prepare, pad, and encrypt an arbitrary input in AES CBC mode
auto const generate_ciphertext = [](std::string const &arbitrary_input, std::string const &key) -> std::string {
  if (auto match = std::smatch{}; std::regex_match(arbitrary_input, match, rgx))
  {
    return hmr::crypto::aes_cbc_encrypt("comment1=cooking%20MCs;userdata=" + arbitrary_input + ";comment2=%20like%20a%20pound%20of%20bacon", key);
  } else
  {
    return std::string{};
  }
};

auto const get_blocks = [](std::string_view ciphertext, std::size_t block_size = 16) -> std::vector<std::string_view> {
  assert(ciphertext.size() % block_size == 0);

  auto output = std::vector<std::string_view>{};

  std::size_t offset = 0;
  while (offset < ciphertext.size())
  {
    output.emplace_back(ciphertext.substr(offset, block_size));
    offset += block_size;
  }

  return output;
};

////////////////////////////////////////////////
void challenge_16()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 16 ]  \n");

  // Random AES key
  std::string const key = hmr::prng::bytes(16);
  spdlog::info("Key: {}", hmr::hex::encode(key));

  // Generate the ciphertext
  std::string const ciphertext = generate_ciphertext("This is some arbitrary text", key);
  spdlog::info("Ciphertext: {}", hmr::hex::encode(ciphertext));

  // Decrypt and look for the text ";admin=true" - this should never happen normally, so we'll need to modify the ciphertext
  std::string const admin_string = ";admin=true"s;
  std::string const plaintext = hmr::crypto::aes_cbc_decrypt(ciphertext, key);
  spdlog::info("Plaintext: {}", plaintext);

  assert(plaintext.find(admin_string) == std::string::npos);

  // In CBC mode, a 1-bit error in a ciphertext block 1) completely scrambles the block the error occurs in; and 2) produces the identical 1-bit error(/edit) in the next ciphertext block
  auto blocks = get_blocks(ciphertext);
  for (auto block : blocks)
  {
    spdlog::info("AES block: {}", hmr::hex::encode(block));
  }
}

} // namespace set_02

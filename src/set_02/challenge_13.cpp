#include "set_02/all_challenges.hpp"

#include <string>
#include <string_view>
#include <regex>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/base64.hpp>
#include <hamarr/crypto.hpp>
#include <hamarr/serialisation.hpp>
#include <hamarr/prng.hpp>

namespace set_02
{

static const auto email_rgx = std::regex{R"([^&=]{1,250}@[^&=]{3,250}$)"};

////////////////////////////////////////////////
auto get_last_block = [](std::string const &ciphertext, std::size_t const block_size = 16) -> std::string {
  std::size_t const len = ciphertext.size();

  if (len % block_size != 0)
  {
    spdlog::warn("Blocksize appears incorrect!");
    return std::string{};
  }

  // How many blocks are there?
  std::size_t const block_count = len / block_size;

  return ciphertext.substr((block_count * block_size) - block_size, block_size);
};


////////////////////////////////////////////////
auto chop_last_block = [](std::string const &ciphertext, std::size_t const block_size = 16) -> std::string {
  std::size_t const len = ciphertext.size();

  if (len % block_size != 0)
  {
    spdlog::warn("Blocksize appears incorrect!");
    return std::string{};
  }

  // How many blocks are there?
  std::size_t const block_count = len / block_size;

  return ciphertext.substr(0, (block_count * block_size) - block_size);
};


////////////////////////////////////////////////
void challenge_13()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 13 ]  \n");

  // Testing k=v parsing routine
  auto const input = std::string{"foo=bar&baz=qux&zap=zazzle"};
  auto const kvps = hmr::kvp::deserialise(input);
  for (auto const &kvp : kvps)
  {
    spdlog::info("{}: {}", kvp.first, kvp.second);
  }

  // Lambda to take an email address string and return a serialised string
  // clang-format off
  auto const profile_for = [](std::string const &email) -> std::string
  {
    if (auto match = std::smatch{}; std::regex_match(email, match, email_rgx))
    {
      auto const profile_kvps = std::map<std::string, std::string>{{"email", email}, {"uid", "10"}, {"role", "user"}};

      // hmr::kvp::serialise(profile_kvps) does not preserve the order, so we need to build the profile by hand to ensure role=user is last
      return "email=" + email + "&uid=10&role=user";
    } else
    {
      return std::string{};
    }
  };
  // clang-format on

  std::string const profile_string = profile_for("foo@bar.com");
  spdlog::info("profile_string generated: {}", profile_string);

  // Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".
  // We'll use a regex to enforce this

  // Random AES key
  std::string const key = hmr::prng::bytes(16);

  // Encrypt the encoded user profile under the key
  std::string const ciphertext = hmr::crypto::aes_ecb_encrypt(profile_string, key);
  spdlog::info("profile_string encrypted: {}", hmr::hex::encode(ciphertext));

  // Decrypt the encoded user profile
  std::string const plaintext = hmr::crypto::aes_ecb_decrypt(ciphertext, key);
  spdlog::info("profile_string decrypted: {}", plaintext);

  // Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile

  // Let's make an email long enough to ensure the trailing "user" is in it's own block
  // "email=" + "&uid=10&role=" == 19 chars, so 32-19 == 13 chars needed for the email
  std::string const fake_profile = profile_for("blah@blah.com");
  spdlog::info("  fake_profile generated: {}", fake_profile);

  // Encrypt the fake user profile under the key
  std::string const fake_profile_ciphertext = hmr::crypto::aes_ecb_encrypt(fake_profile, key);
  spdlog::info("  fake_profile encrypted: {}", hmr::hex::encode(fake_profile_ciphertext));

  // Decrypt the final block to check it only says "user"
  std::string const final_block = get_last_block(fake_profile_ciphertext);
  std::string const final_block_plaintext = hmr::crypto::aes_ecb_decrypt(final_block, key);
  spdlog::info("   final block decrypted: {}", final_block_plaintext);

  // Create a block that just says "admin"
  std::string const admin_ciphertext = hmr::crypto::aes_ecb_encrypt("admin", key);
  spdlog::info("   admin block encrypted: {}", hmr::hex::encode(admin_ciphertext));

  // Swap the final block of the fake_profile with the admin ciphertext
  std::string const forged_ciphertext = chop_last_block(fake_profile_ciphertext) + admin_ciphertext;
  spdlog::info("forged profile encrypted: {}", hmr::hex::encode(forged_ciphertext));

  // Decrypt the forged ciphertext and check it's an admin profile
  std::string const forged_plaintext = hmr::crypto::aes_ecb_decrypt(forged_ciphertext, key);
  spdlog::info("forged profile decrypted: {}", forged_plaintext);

  // Parse the profile
  auto const forged_kvps = hmr::kvp::deserialise(forged_plaintext);

  // Is it a proper admin profile?
  if (forged_kvps.at("role") == "admin")
  {
    spdlog::info("Forged profile correctly identified as an admin role!");
  }
}

} // namespace set_02

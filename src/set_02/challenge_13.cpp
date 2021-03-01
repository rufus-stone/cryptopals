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

      return hmr::kvp::serialise(profile_kvps);
    } else
    {
      return std::string{};
    }
  };
  // clang-format on

  std::string const profile_string = profile_for("foo@bar.com");
  spdlog::info("profile_string: {}", profile_string);

  // Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

  // Random AES key
  std::string const key = hmr::prng::bytes(16);

  // Encrypt the encoded user profile under the key
  std::string const ciphertext = hmr::crypto::aes_ecb_encrypt(profile_string, key);
  spdlog::info(hmr::hex::encode(ciphertext));

  // Decrypt the encoded user profile and parse it
  std::string const plaintext = hmr::crypto::aes_ecb_decrypt(ciphertext, key);
  spdlog::info(plaintext);

  // Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile
}

} // namespace set_02

#include "set_01/all_challenges.hpp"

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/bitwise.hpp>
#include <hamarr/analysis.hpp>

namespace set_01
{

using namespace std::string_literals;

////////////////////////////////////////////////
void challenge_03()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 3 ]  \n");

  auto data = hmr::hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"s);

  spdlog::info("Input   : {}", hmr::hex::encode(data));

  uint8_t key = 0x00;

  auto possible_keys = std::vector<uint8_t>{};

  // Iterate through all possible single byte keys
  for (std::size_t n = 0; n <= std::numeric_limits<uint8_t>::max(); ++n)
  {
    auto result = hmr::bitwise::xor_with_key(data, key);

    if (hmr::analysis::looks_like_english(result))
    {
      possible_keys.push_back(key);
    }

    key++;
  }

  if (possible_keys.size() == 1)
  {
    spdlog::info("XOR key : {}", hmr::hex::encode(possible_keys[0]));
    spdlog::info("Output  : {}", hmr::bitwise::xor_with_key(data, possible_keys[0]));
  } else
  {
    spdlog::info("Found {} candidate keys:", possible_keys.size());

    for (const auto &k : possible_keys)
    {
      spdlog::info("XOR key : {}", hmr::hex::encode(k));
      spdlog::info("Output  : {}", hmr::bitwise::xor_with_key(data, k));
    }
  }
}

} // namespace set_01

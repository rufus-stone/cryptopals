#include "set_01/all_challenges.hpp"

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/base64.hpp>

namespace set_01
{

////////////////////////////////////////////////
void challenge_01()
{
  using namespace std::string_literals;

  spdlog::info("\n\n  [ Set 1 : Challenge 1 ]  \n");

  auto data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"s;
  auto expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"s;

  auto result = hmr::base64::encode(hmr::hex::decode(data));

  spdlog::info("Input  : {}", data);

  spdlog::info("Output : {}", result);

  assert(result == expected_result);
}

} // namespace set_01

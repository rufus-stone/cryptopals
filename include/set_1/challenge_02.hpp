#pragma once

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/bitwise.hpp>

namespace set_01::challenge_02
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 2 ]  \n");

  auto data = hmr::hex::decode("1c0111001f010100061a024b53535009181c"s);
  auto key = hmr::hex::decode("686974207468652062756c6c277320657965"s);
  auto expected_result = hmr::hex::decode("746865206b696420646f6e277420706c6179"s);

  auto result = hmr::bitwise::xor_with_key(data, key);

  spdlog::info("Input   : {}", hmr::hex::encode(data));
  spdlog::info("XOR key : {}", hmr::hex::encode(key));

  spdlog::info("Output  : {}", hmr::hex::encode(result));

  assert(result == expected_result);
}

} // namespace set_01::challenge_02

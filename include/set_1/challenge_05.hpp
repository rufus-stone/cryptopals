#pragma once

#include <cassert>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/bitwise.hpp>

namespace set_01::challenge_05
{

////////////////////////////////////////////////
void run()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 5 ]  \n");

  auto data = std::string{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"};
  
  auto result = hmr::bitwise::xor_with_key(data, "ICE");

  assert(result == hmr::hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));

  spdlog::info("Input   : {}", data);
  spdlog::info("XOR key : ICE");
  spdlog::info("Output  : {}", hmr::hex::encode(result));
}

} // namespace set_01::challenge_05

#pragma once

#include <string>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/analysis.hpp>

namespace set_02::challenge_11
{

////////////////////////////////////////////////
void run()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 11 ]  \n");

  auto result = cp::encrypt_under_random_key_and_mode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  spdlog::info(hmr::hex::encode(result));
  spdlog::info(hmr::analysis::repeated_blocks(result));
}

} // namespace set_02::challenge_11

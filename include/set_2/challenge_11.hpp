#pragma once

#include <string>

#include "utils.hpp"

namespace set_02::challenge_11
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 2 : Challenge 11 ]  \n");

  auto result = cp::encrypt_under_random_key_and_mode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  LOG_INFO(hmr::hex::encode(result));
  LOG_INFO(std::boolalpha << hmr::analysis::repeated_blocks(result));
}

} // namespace set_02::challenge_11
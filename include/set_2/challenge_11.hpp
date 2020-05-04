#pragma once

#include <string>

#include "utils.hpp"

namespace set_02::challenge_11
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 2 : Challenge 11 ]  \n");

  auto result = cp::encrypt_under_random_key_and_mode("This is a really banging test string, whatwhaaaaaaat!");

  LOG_INFO(hmr::hex::encode(result));
}

} // namespace set_02::challenge_11
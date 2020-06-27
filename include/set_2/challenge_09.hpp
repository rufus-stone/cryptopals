#pragma once

#include <string>

#include "hamarr.hpp"

namespace set_02::challenge_09
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 2 : Challenge 9 ]  \n");

  auto data = std::string{"YELLOW SUBMARINE"};
  auto expected_result = std::string{"YELLOW SUBMARINE\x04\x04\x04\x04"};

  auto result = hmr::pkcs7::pad(data, 20);

  LOG_INFO("Input  : " << data);

  LOG_INFO("Output : " << hmr::format::escape(result));

  assert(result == expected_result);
}

} // namespace set_02::challenge_09
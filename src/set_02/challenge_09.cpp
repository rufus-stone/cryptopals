#include "set_02/all_challenges.hpp"

#include <string>

#include <spdlog/spdlog.h>

#include <hamarr/format.hpp>
#include <hamarr/pkcs7.hpp>

namespace set_02
{

////////////////////////////////////////////////
void challenge_09()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 9 ]  \n");

  auto data = std::string{"YELLOW SUBMARINE"};
  auto expected_result = std::string{"YELLOW SUBMARINE\x04\x04\x04\x04"};

  auto result = hmr::pkcs7::pad(data, 20);

  spdlog::info("Input  : {}", data);

  spdlog::info("Output : {}", hmr::fmt::escape(result));

  assert(result == expected_result);
}

} // namespace set_02

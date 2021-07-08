#include "set_02/all_challenges.hpp"

#include <string>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/analysis.hpp>

#include "utils/crypto.hpp"

namespace set_02
{

////////////////////////////////////////////////
void challenge_11()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 11 ]  \n");

  std::string const result = cp::encrypt_under_random_key_and_mode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  spdlog::info(hmr::hex::encode(result));
  spdlog::info(hmr::analysis::repeated_blocks(result));
}

} // namespace set_02

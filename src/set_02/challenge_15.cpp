#include "set_02/all_challenges.hpp"

#include <string>
#include <string_view>

#include <spdlog/spdlog.h>

#include <hamarr/pkcs7.hpp>
#include <hamarr/format.hpp>

namespace set_02
{

using namespace std::string_view_literals;

////////////////////////////////////////////////
void challenge_15()
{
  spdlog::info("\n\n  [ Set 2 : Challenge 15 ]  \n");

  std::string_view valid_padding = "ICE ICE BABY\x04\x04\x04\x04"sv;
  std::string_view invalid_padding_1 = "ICE ICE BABY\x05\x05\x05\x05"sv;
  std::string_view invalid_padding_2 = "ICE ICE BABY\x01\x02\x03\x04"sv;

  spdlog::info("PKCS7 padded? {} == {}", hmr::fmt::escape(valid_padding), hmr::pkcs7::padded(valid_padding));
  spdlog::info("PKCS7 padded? {} == {}", hmr::fmt::escape(invalid_padding_1), hmr::pkcs7::padded(invalid_padding_1));
  spdlog::info("PKCS7 padded? {} == {}", hmr::fmt::escape(invalid_padding_2), hmr::pkcs7::padded(invalid_padding_2));
}

} // namespace set_02

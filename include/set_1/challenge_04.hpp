#pragma once

#include <cpr/cpr.h>

namespace set_01::challenge_04
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  // Get the file - disable SSL verification as otherw we get the error: "SSL certificate problem: unable to get local issuer certificate"
  auto result = cpr::Get(cpr::Url{"https://cryptopals.com/static/challenge-data/4.txt"}, cpr::VerifySsl{false});

  const std::string data = result.text;

  // Split into vector around newline chars

  //" etaoinsrhldcumfgpyw\x0Ab,.vk-\"_'x)(;0j1q=2:z/*!?$35>{}49[]867\\+|&<%@#^`~"s;
  static const auto english_freqs = hex::decode("20 65 74 61 6f 69 6e 73 72 68 6c 64 63 75 6d 66 67 70 79 77 0a 62 2c 2e 76 6b 2d 5c 22 5f 27 78 29 28 3b 30 6a 31 71 3d 32 3a 7a 2f 2a 21 3f 24 33 35 3e 7b 7d 34 39 5b 5d 38 36 37 5c 5c 2b 7c 26 3c 25 40 23 5e 60 7e");

  // Get vector of character freqs
  auto freqs = analysis::character_frequency(data, analysis::case_sensitivity::disabled);

}

} // namespace set_01::challenge_04
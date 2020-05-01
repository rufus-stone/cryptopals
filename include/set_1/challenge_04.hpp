#pragma once

#include <cpr/cpr.h>

#include <fstream> // For file i/o
#include <filesystem> // For filesystem stuff
#include <cstdlib> // For getting the path to the home dire

#include "downloader.hpp"

namespace set_01::challenge_04
{

using namespace std::string_literals;

//" etaoinsrhldcumfgpyw\x0Ab,.vk-\"_'x)(;0j1q=2:z/*!?$35>{}49[]867\\+|&<%@#^`~"s;
static const auto english_freqs = hex::decode("20 65 74 61 6f 69 6e 73 72 68 6c 64 63 75 6d 66 67 70 79 77 0a 62 2c 2e 76 6b 2d 5c 22 5f 27 78 29 28 3b 30 6a 31 71 3d 32 3a 7a 2f 2a 21 3f 24 33 35 3e 7b 7d 34 39 5b 5d 38 36 37 5c 5c 2b 7c 26 3c 25 40 23 5e 60 7e");

std::vector<std::string> split(const std::string &input, const char delim = '\n')
{
  auto output = std::vector<std::string>{};

  std::size_t line_start = 0;
  std::size_t line_end = input.find_first_of(delim);
  
  if (line_end != std::string::npos)
  {
    LOG_INFO("Newline at offset: " << line_end);
    auto tmp = std::string(input.data() + line_start, input.data() + line_end);
    LOG_INFO(tmp);

  } else
  {
    LOG_INFO("Last line:");
    auto tmp = std::string(input.data());
    LOG_INFO(tmp);
  }
  

  return output;
}

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 4 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/4.txt", 1, 4);

  auto data_vec = cp::file_to_vector(file_path);

  // Loop through the challenge data - one of these has been XORed with a single char key, the rest are gibberish
  for (const auto &data : data_vec)
  {
    auto possible_keys = hmr::analysis::solve_single_byte_xor(hmr::hex::decode(data));

    if (!possible_keys.empty())
    {
      LOG_INFO("Found " << possible_keys.size() << " candidate keys:");
      for (const auto &key : possible_keys)
      {
        LOG_INFO("Input   : " << data);
        LOG_INFO("XOR key : " << hex::encode(key));
        LOG_INFO("Output  : " << hmr::bitwise::xor_with_key(hmr::hex::decode(data), key));
      }
    }
  }
}

} // namespace set_01::challenge_04

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

  if (!std::filesystem::exists(file_path))
  {
    LOG_ERROR("Failed to get data for Set 1 : Challenge 4!");
    return;
  }

  // Open the file
  auto file_in = std::ifstream{file_path, std::ios::binary};

  // Read in a line at a time
  auto line = std::string{};
  auto data_vec = std::vector<std::string>{};
  while (std::getline(file_in, line))
  {
    data_vec.push_back(std::move(line));
  }

  // Close the file if necessary - not sure this is needed...
  if (file_in.is_open())
  {
    file_in.close();
  }

  // Abort condition - did we read any lines?
  if (data_vec.empty())
  {
    LOG_ERROR("Failed to read any lines from file!");
    return;
  }

  // Loop through the challenge data - one of these has been XORed with a single char key, the rest are gibberish
  for (const auto data : data_vec)
  {
    uint8_t key = 0x00;

    auto possible_keys_map = std::map<uint8_t, std::string>{};

    // Iterate through all possible single byte keys
    for (std::size_t n = 0; n <= std::numeric_limits<uint8_t>::max(); ++n)
    {
      auto result = bitwise::xor_with_key(hex::decode(data), key);

      if (analysis::looks_like_english(result))
      {
        possible_keys_map.insert({key, result});
      }

      key++;
    }

    if (possible_keys_map.size() > 0)
    {
      LOG_INFO("Found " << possible_keys_map.size() << " candidate keys:");
      for (const auto &kvp : possible_keys_map)
      {
        LOG_INFO("Input   : " << data);
        LOG_INFO("XOR key : " << hex::encode(kvp.first));
        LOG_INFO("Output  : " << kvp.second);
      }
    }
  }
}

} // namespace set_01::challenge_04

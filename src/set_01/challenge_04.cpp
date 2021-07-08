#include "set_01/all_challenges.hpp"

#include <fstream> // For file i/o
#include <filesystem> // For filesystem stuff
#include <cstdlib> // For getting the path to the home directory

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/bitwise.hpp>
#include <hamarr/analysis.hpp>

#include "utils/downloader.hpp"

namespace set_01
{
//" etaoinsrhldcumfgpyw\x0Ab,.vk-\"_'x)(;0j1q=2:z/*!?$35>{}49[]867\\+|&<%@#^`~"s;

////////////////////////////////////////////////
void challenge_04()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 4 ]  \n");

  std::filesystem::path const file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/4.txt", 1, 4);

  std::vector<std::string> const data_vec = cp::file_to_vector(file_path);

  // Loop through the challenge data - one of these has been XORed with a single char key, the rest are gibberish
  for (std::string const &data : data_vec)
  {
    std::vector<uint8_t> const possible_keys = hmr::analysis::solve_single_byte_xor(hmr::hex::decode(data));

    if (!possible_keys.empty())
    {
      spdlog::info("Found {} candidate keys:", possible_keys.size());
      for (uint8_t const key : possible_keys)
      {
        spdlog::info("Input   : {}", data);
        spdlog::info("XOR key : {}", hmr::hex::encode(key));
        spdlog::info("Output  : {}", hmr::bitwise::xor_with_key(hmr::hex::decode(data), key));
      }
    }
  }
}

} // namespace set_01

#include "set_01/all_challenges.hpp"

#include <cassert>

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/analysis.hpp>

#include "utils/downloader.hpp"

namespace set_01
{

////////////////////////////////////////////////
void challenge_08()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 8 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/8.txt", 1, 8);

  std::vector<std::string> const data_vec = cp::file_to_vector(file_path);

  for (std::string const &data : data_vec)
  {
    // For each 16 byte block, check if the same 16 byte block occurs later on in the string
    std::string const decoded = hmr::hex::decode(data);
    auto data_view = std::string_view{decoded};

    if (hmr::analysis::repeated_blocks(data_view))
    {
      spdlog::info("Found repeated block in: {}", data);
      break;
    }
  }
}

} // namespace set_01

#pragma once

#include <cassert>

#include "downloader.hpp"

namespace set_01::challenge_08
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 8 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/8.txt", 1, 8);

  auto data_vec = cp::file_to_vector(file_path);

  for (const auto &data : data_vec)
  {
    // For each 16 byte block, check if the same 16 byte block occurs later on in the string
    auto decoded = hmr::hex::decode(data);
    auto data_view = std::string_view{decoded};

    if (hmr::analysis::repeated_blocks(data_view))
    {
      LOG_INFO("Found repeated block in: " << data);
      break;
    }
  }
}

} // namespace set_01::challenge_08

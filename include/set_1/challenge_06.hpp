#pragma once

#include "downloader.hpp"

namespace set_01::challenge_06
{

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 6 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/6.txt", 1, 6);

  if (!std::filesystem::exists(file_path))
  {
    LOG_ERROR("Failed to get data for Set 1 : Challenge 6!");
    return;
  }

  // Open the file
  auto file_in = std::ifstream{file_path, std::ios::binary};

  // Read in a line at a time
  auto line = std::string{};
  auto data = std::string{};
  while (std::getline(file_in, line))
  {
    data += line;
  }

  // Close the file if necessary - not sure this is needed...
  if (file_in.is_open())
  {
    file_in.close();
  }

  // Abort condition - did we read any lines?
  if (data.empty())
  {
    LOG_ERROR("Failed to read any data from file!");
    return;
  }

  auto decoded = hmr::base64::decode(data);

  if (decoded.empty())
  {
    LOG_ERROR("Failed to base64 decode data!");
  }

  
}

} // namespace set_01::challenge_06

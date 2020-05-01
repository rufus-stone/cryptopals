#pragma once

#include <cassert>

namespace set_01::challenge_08
{

bool has_repeated_blocks(std::string_view input, std::size_t block_size = 16)
{
  auto len = input.size();
  assert(len % block_size == 0);

  for (std::size_t offset = 0; offset + block_size <= (len - block_size); offset += block_size) // go until len - 16 so that we ignore the final block, as we'll already know this isn't the ECB we're looking for by that point
  {
    // Get the next block
    auto block = input.substr(offset, block_size);

    // Does this block occur again in the data
    auto pos = input.find(block, offset + block_size);
    if (pos != std::string_view::npos)
    {
      LOG_INFO("Data:  " << hmr::hex::encode(input));
      LOG_INFO("Block: " << hmr::hex::encode(block));
      LOG_INFO("Found same block at offset: " << pos);
      return true;
    }
  }

  return false;
}

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

    if (has_repeated_blocks(data_view))
    {
      break;
    }
  }
}

} // namespace set_01::challenge_08

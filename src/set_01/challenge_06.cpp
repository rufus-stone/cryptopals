#include "set_01/all_challenges.hpp"

#include <spdlog/spdlog.h>

#include <hamarr/hex.hpp>
#include <hamarr/base64.hpp>
#include <hamarr/bitwise.hpp>
#include <hamarr/analysis.hpp>

#include "utils/downloader.hpp"

namespace set_01
{

////////////////////////////////////////////////
void challenge_06()
{
  spdlog::info("\n\n  [ Set 1 : Challenge 6 ]  \n");

  auto file_path = cp::download_challenge_data("https://cryptopals.com/static/challenge-data/6.txt", 1, 6);

  auto data = cp::file_to_string(file_path);

  auto decoded = hmr::base64::decode(data);

  if (decoded.empty())
  {
    spdlog::error("Failed to base64 decode data!");
  }

  // Let's work with a string view, for more efficient sub-string creation
  auto data_view = std::string_view{decoded};
  const std::size_t len = data_view.size();

  // Find the most likely key_size
  auto best_key_size = hmr::analysis::find_candidate_keysize(data_view).first;

  // Now that we know the most likely key_size, break the input up into as many blocks of key_size length as possible (we can ignore any extra data that doesn't fit)
  auto max_blocks = len / best_key_size;
  auto blocks = std::vector<std::string_view>{};
  blocks.reserve(max_blocks);

  // Chunk the data into blocks of best_key_size length
  for (int i = 0; i + best_key_size < len; i += best_key_size)
  {
    auto lhs = data_view.substr(i, best_key_size);
    blocks.push_back(lhs);
  }

  // Now transpose each byte of each block together
  auto transposed_blocks = std::vector<std::string>(best_key_size, std::string{});

  for (const auto &block : blocks)
  {
    assert(block.size() == best_key_size);

    for (std::size_t i = 0; i < best_key_size; ++i)
    {
      transposed_blocks[i].push_back(block[i]);
    }
  }

  // Now solve each transposed_block as though it were a single byte XOR
  auto probable_key = std::string{};
  for (const auto &transposed_block : transposed_blocks)
  {
    auto xor_keys = hmr::analysis::solve_single_byte_xor(transposed_block);

    if (xor_keys.size() == 1)
    {
      probable_key.push_back(xor_keys[0]);

    } else
    {
      spdlog::info("Found {} candidate keys for:", xor_keys.size());
      spdlog::info(hmr::hex::encode(transposed_block));

      for (const auto &xor_key : xor_keys)
      {
        spdlog::info("Key: {}", hmr::hex::encode(xor_key));
      }

      // We'll need to handle this situation if it arises!
    }
  }

  // If we successfully found a single ideal XOR key for each of the single byte XOR tests, let's try it out!
  if (probable_key.size() == best_key_size)
  {
    spdlog::info("XOR key is probably: {}", hmr::hex::encode(probable_key));

    spdlog::info("Trying the key...\n");

    // Try the key!
    auto result = hmr::bitwise::xor_with_key(data_view, probable_key);

    if (hmr::analysis::looks_like_english(result, true))
    {
      spdlog::info("Output :\n\n{}", result);
    } else
    {
      spdlog::info("Hmm, not quite right...");
    }
  }
}

} // namespace set_01

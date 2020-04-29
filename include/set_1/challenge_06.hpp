#pragma once

#include "downloader.hpp"

namespace set_01::challenge_06
{

auto find_candidate_keysize(std::string_view input, std::size_t min = 2, std::size_t max = 40)
{
  const std::size_t len = input.size();

  const std::size_t min_key_size = min;
  const std::size_t max_key_size = max;
  
  auto average_hams = std::vector<std::pair<std::size_t, double>>{};
  average_hams.reserve(max_key_size - min_key_size);

  // For all possible key_sizes between min and max, figure out the most likely key_size
  for (std::size_t key_size = min_key_size; key_size <= max_key_size; ++key_size)
  {
    // How many pairs of key_size worth of bytes can we take?
    auto num_pairs = len / (key_size * 2);

    auto hams = std::vector<double>{};
    hams.reserve(num_pairs);

    // Take each pair of key_size worth of bytes
    for (int i = 0; i + (key_size * 2) < len; i += (key_size * 2))
    {
      auto lhs = input.substr(i, key_size);
      auto rhs = input.substr(i + key_size, key_size);

      // Compute the hamming distance, and normalise by dividing by key_size
      double ham_norm = hmr::analysis::hamming_distance(lhs, rhs);
      ham_norm /= key_size;

      hams.push_back(ham_norm);
    }

    // Now average the hamming distances
    auto average_ham = std::accumulate(std::begin(hams), std::end(hams), 0.0) / hams.size();
    
    // Make a note of the hamming distance for the current key_size
    average_hams.emplace_back(std::make_pair(key_size, average_ham));
  }

  // Which key_size has the lowest average hamming distance, and is therefore the best candidate for the actual key size?
  auto best_candidate = std::min_element(std::begin(average_hams), std::end(average_hams), [](const auto &lhs, const auto &rhs) { return lhs.second < rhs.second; });
  LOG_INFO("Best candidate key size: " << best_candidate->first << " (average Hamming distance: " << best_candidate->second << ")");

  return *best_candidate;
}

bool looks_good(std::string_view input, bool flag = false)
{
  std::size_t spaces = 0;
  std::size_t punctuation = 0;
  std::size_t numbers = 0;
  std::size_t lowercase = 0;
  std::size_t uppercase = 0;

  for (const auto &c : input)
  {
    auto ch = static_cast<uint8_t>(c);

    // Abort condition - there should be no un-printable byte values (apart from space, tab, newline, carriage return, etc.)
    if ((ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0B && ch != 0x0C && ch != 0x0D) || ch > 0x7E)
    {
      if (flag) LOG_INFO("Failed unprintable");
      return false;
    }

    // Is it a space char?
    if (ch == 0x20)
    {
      ++spaces;
    }

    // Is it a punctuation char?
    if ((ch >= 0x21 && ch <= 0x2F) || (ch >= 0x3A && ch <= 0x40) || (ch >= 0x5B && ch <= 0x60) || (ch >= 0x7B && ch <= 0x7E))
    {
      ++punctuation;
    }

    // Is it a number?
    if (ch >= 0x30 && ch <= 0x39)
    {
      ++numbers;
    }

    // Is it a lowercase letter?
    if (ch >= 0x61 && ch <= 0x7A)
    {
      ++lowercase;
    }

    // Is it an uppercase letter?
    if (ch >= 0x41 && ch <= 0x5A)
    {
      ++uppercase;
    }
  }

  // There should be more spaces than punctuation
  if (spaces < punctuation)
  {
    if (flag) LOG_INFO("Failed spaces vs punc");
    return false;
  }

  // There should be more alphanumerics than punctuation
  if (numbers + lowercase + uppercase < punctuation)
  {
    if (flag) LOG_INFO("Failed alphanum vs punc");
    return false;
  }

  // There should be more lowercase letters than uppercase
  if (lowercase < uppercase)
  {
    if (flag) LOG_INFO("Failed lower vs upper");
    return false;
  }

  // There should be more letters than numbers
  if (lowercase + uppercase < numbers)
  {
    if (flag) LOG_INFO("Failed letters vs numbers");
    return false;
  }

  return true;
}

auto solve_single_byte_xor(std::string_view input)
{
  uint8_t key = 0x00;

  auto possible_keys = std::vector<uint8_t>{};

  // Iterate through all possible single byte keys
  for (std::size_t n = 0; n <= std::numeric_limits<uint8_t>::max(); ++n)
  {
    auto result = bitwise::xor_with_key(input, key);

    if (looks_good(result))
    {
      possible_keys.push_back(key);
    }
    

    key++;
  }

  if (possible_keys.empty())
  {
    LOG_INFO("Failed to find any possible keys!");
    LOG_INFO("Input was: " << input);
  }

  return possible_keys;
}

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

  // Let's work with a string view, for more efficient sub-string creation
  auto data_view = std::string_view{decoded};
  const std::size_t len = data_view.size();

  // Find the most likely key_size
  auto best_key_size = find_candidate_keysize(data_view).first;
  
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
    auto xor_keys = solve_single_byte_xor(transposed_block);

    if (xor_keys.size() == 1)
    {
      probable_key.push_back(xor_keys[0]);

    } else
    {
      LOG_INFO("Found " << xor_keys.size() << " candidate keys for:");
      LOG_INFO(hmr::hex::encode(transposed_block));

      for (const auto &xor_key : xor_keys)
      {
        LOG_INFO("Key: " << hmr::hex::encode(xor_key));
      }

      // We'll need to handle this situation if it arises!
    }
  }

  // If we successfully found a single ideal XOR key for each of the single byte XOR tests, let's try it out!
  if (probable_key.size() == best_key_size)
  {
    LOG_INFO("\nXOR key is probably: " << hex::encode(probable_key));

    LOG_INFO("\nTrying the key...\n");

    // Try the key!
    auto result = hmr::bitwise::xor_with_key(data_view, probable_key);

    if (looks_good(result, true))
    {
      LOG_INFO(result);
    } else
    {
      LOG_INFO("Hmm, not quite right...");
    }
  }
}

} // namespace set_01::challenge_06

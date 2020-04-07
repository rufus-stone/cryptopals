#pragma once


#include "test_text.hpp"

namespace set_01::challenge_03
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 3 ]  \n");

  auto data = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"s);

  LOG_INFO("Input: " << hex::encode(data));


  auto try_all_keys = [](const std::string &input)
  {
    uint8_t key = 0x00;

    auto is_candidate_plaintext = [](const auto &input) -> bool
    {
      // There should be more alphanumeric chars than punctuation chars
      std::size_t alphanumerics = 0;
      std::size_t punctuation = 0;

      // There should be at least some space chars
      bool spaces = false;

      // Compute the character frequencies
      auto freqs = analysis::character_frequency(input, analysis::case_sensitivity::disabled);

      // Todo - maybe change this to a std::array in the utils lib to ensure it's always exactly 256 elements in size, and can't be modified
      assert(freqs.size() == 256);

      // Iterate through the freqs vector and run some checks
      for (std::size_t i = 0; i < freqs.size(); ++i)
      {
        auto ch = static_cast<uint8_t>(i);

        // Were there any of the current char present?
        if (freqs[i] > 0)
        {
          // Abort condition - there should be no un-printable byte values
          if (ch < 0x20 || ch > 0x7E)
          {
            return false;
          }

          // Are there any space chars?
          if (ch == 0x20)
          {
            spaces = true;
          }

          // Update the count of punctuation chars vs alphanumeric chars
          if ((ch >= 0x21 && ch <= 0x2F) || (ch >= 0x3A && ch <= 0x40) || (ch >= 0x5B && ch <= 0x60) || (ch >= 0x7B && ch <= 0x7E))
          {
            ++punctuation;

          } else
          {
            ++alphanumerics;
          }
        }
      }

      // The average word length in English is 4.7
      auto word_lengths = std::vector<std::size_t>{};
      std::size_t current_word_length = 0;
      double average_word_length = 0;

      // Iterate through the raw input and run some more checks
      for (const auto &c : input)
      {
        auto ch = static_cast<uint8_t>(c);

        // Is it an uppercase or lowercase alphabet char, or an apostraphe? If so, increment the length of the current word
        if ((ch >= 0x41 && ch <= 0x5A) || (ch >= 0x61 && ch <= 0x7A) || ch == 0x27)
        {
          ++current_word_length;

        // Otherwise the word must be over
        } else
        {
          // If appropriate, update the vector of all word_lengths with the length of this word
          if (current_word_length > 0)
          {
            word_lengths.push_back(current_word_length);
          }
          
          // Reset the current word length
          current_word_length = 0;
        }
      }

      // Add any final word length
      if (current_word_length > 0)
      {
        word_lengths.push_back(current_word_length);
        current_word_length = 0;
      }

      // Abort condition - there should be more alphanumerics than punctuation chars
      if (punctuation > alphanumerics)
      {
        return false;
      }

      // Abort condition - there should be at least some space chars
      if (spaces == false)
      {
        return false;
      }

      // Compute the mean average word length
      average_word_length = std::accumulate(std::begin(word_lengths), std::end(word_lengths), 0.0) / word_lengths.size();

      // Abort condition - the average word length should be between 3.5 and 6.5 chars (the real average for English is 4.7)
      if (average_word_length <= 3.5 || average_word_length >= 6.5)
      {
        return false;
      }

      return true;
    };

    // Iterate through all possible single byte keys
    for (std::size_t n = 0; n <= std::numeric_limits<uint8_t>::max(); ++n)
    {
      auto result = bitwise::xor_with_key(input, key);

      if (is_candidate_plaintext(result))
      {
        LOG_INFO("Key " << hex::encode(key) << " looks promising: " << result);
      }

      key++;
    }
  };

  try_all_keys(data);
}

} // namespace set_01::challenge_03
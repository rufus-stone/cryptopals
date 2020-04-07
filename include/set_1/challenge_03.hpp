#pragma once

namespace set_01::challenge_03
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 3 ]  \n");

  auto data = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"s);

  LOG_INFO("Input   : " << hex::encode(data));

  uint8_t key = 0x00;

  auto possible_keys = std::vector<uint8_t>{};

  // Iterate through all possible single byte keys
  for (std::size_t n = 0; n <= std::numeric_limits<uint8_t>::max(); ++n)
  {
    auto result = bitwise::xor_with_key(data, key);

    if (analysis::looks_like_english(result))
    {
      //LOG_INFO("Key " << hex::encode(key) << " looks like English: " << result);
      possible_keys.push_back(key);
    }

    key++;
  }

  if (possible_keys.size() == 1)
  {
    LOG_INFO("XOR key : " << hex::encode(possible_keys[0]));
    LOG_INFO("Output  : " << bitwise::xor_with_key(data, possible_keys[0]));
  } else
  {
    LOG_INFO("Found " << possible_keys.size() << " candidate keys:");

    for (const auto &k : possible_keys)
    {
      LOG_INFO("XOR key : " << hex::encode(k));
      LOG_INFO("Output  : " << bitwise::xor_with_key(data, k));
    }
  }
}

} // namespace set_01::challenge_03

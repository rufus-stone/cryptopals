#pragma once

namespace set_01::challenge_02
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 2 ]  \n");

  auto data = hex::decode("1c0111001f010100061a024b53535009181c"s);
  auto key = hex::decode("686974207468652062756c6c277320657965"s);
  auto expected_result = hex::decode("746865206b696420646f6e277420706c6179"s);

  auto result = bitwise::xor_with_key(data, key);

  LOG_INFO("Data:\n\n" << hex::encode(data));
  LOG_INFO("Key:\n\n" << hex::encode(key));

  LOG_INFO("Result:\n\n" << hex::encode(result));

  assert(result == expected_result);
}

} // namespace set_01::challenge_02
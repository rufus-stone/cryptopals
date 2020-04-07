#pragma once

namespace set_01::challenge_03
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 3 ]  \n");

  auto data = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"s);

  LOG_INFO("Data:\n\n" << hex::encode(data));
}

} // namespace set_01::challenge_03
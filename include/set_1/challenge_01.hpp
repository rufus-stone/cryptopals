#pragma once

namespace set_01::challenge_01
{

using namespace std::string_literals;

////////////////////////////////////////////////
void run()
{
  LOG_INFO("\n\n  [ Set 1 : Challenge 1 ]  \n");

  auto data = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"s;
  auto expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"s;

  auto result = base64::encode(hex::decode(data));

  LOG_INFO("Data:\n\n" << data);

  LOG_INFO("Result:\n\n" << result);

  assert(result == expected_result);
}

} // namespace set_01::challenge_01
#pragma once

#include <cpr/cpr.h>

namespace set_01::challenge_04
{

////////////////////////////////////////////////
void run()
{
  // Get the file - disable SSL verification as otherw we get the error: "SSL certificate problem: unable to get local issuer certificate"
  //auto r = cpr::Get(cpr::Url{"https://cryptopals.com/static/challenge-data/4.txt"}, cpr::VerifySsl{false});

}

} // namespace set_01::challenge_04
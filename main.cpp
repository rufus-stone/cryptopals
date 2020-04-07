#include <iostream>

#include <cpr/cpr.h>

int main()
{
  // Get the file - disable SSL verification as otherw we get the error: "SSL certificate problem: unable to get local issuer certificate"
  auto r = cpr::Get(cpr::Url{"https://cryptopals.com/static/challenge-data/4.txt"}, cpr::VerifySsl{false});
}

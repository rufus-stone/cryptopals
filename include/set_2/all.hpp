#pragma once

#include "challenge_09.hpp"
#include "challenge_10.hpp"
#include "challenge_11.hpp"
#include "challenge_12.hpp"
//#include "challenge_13.hpp"
//#include "challenge_14.hpp"
//#include "challenge_15.hpp"
//#include "challenge_16.hpp"

namespace set_02
{

void run_all()
{
  hmr::profile::benchmark(set_02::challenge_09::run);
  hmr::profile::benchmark(set_02::challenge_10::run);
  hmr::profile::benchmark(set_02::challenge_11::run);
  hmr::profile::benchmark(set_02::challenge_12::run);
  //hmr::profile::benchmark(set_02::challenge_13::run);
  //hmr::profile::benchmark(set_02::challenge_14::run);
  //hmr::profile::benchmark(set_02::challenge_15::run);
  //hmr::profile::benchmark(set_02::challenge_16::run);
}

} // namespace set_02

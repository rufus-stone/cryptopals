#pragma once

#include <hamarr/profiling.hpp>

namespace set_02
{

void challenge_09();
void challenge_10();
void challenge_11();
void challenge_12();
void challenge_13();
void challenge_14();
void challenge_15();
void challenge_16();

inline void run_all()
{
  hmr::profile::benchmark(set_02::challenge_09);
  hmr::profile::benchmark(set_02::challenge_10);
  hmr::profile::benchmark(set_02::challenge_11);
  hmr::profile::benchmark(set_02::challenge_12);
  hmr::profile::benchmark(set_02::challenge_13);
  //hmr::profile::benchmark(set_02::challenge_14);
  //hmr::profile::benchmark(set_02::challenge_15);
  //hmr::profile::benchmark(set_02::challenge_16);
}

} // namespace set_02

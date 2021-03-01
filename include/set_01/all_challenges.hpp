#pragma once

#include <hamarr/profiling.hpp>

namespace set_01
{

void challenge_01();
void challenge_02();
void challenge_03();
void challenge_04();
void challenge_05();
void challenge_06();
void challenge_07();
void challenge_08();

inline void run_all()
{
  hmr::profile::benchmark(set_01::challenge_01);
  hmr::profile::benchmark(set_01::challenge_02);
  hmr::profile::benchmark(set_01::challenge_03);
  hmr::profile::benchmark(set_01::challenge_04);
  hmr::profile::benchmark(set_01::challenge_05);
  hmr::profile::benchmark(set_01::challenge_06);
  hmr::profile::benchmark(set_01::challenge_07);
  hmr::profile::benchmark(set_01::challenge_08);
}

} // namespace set_01

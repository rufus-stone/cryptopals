#pragma once

#include "challenge_01.hpp"
#include "challenge_02.hpp"
#include "challenge_03.hpp"
#include "challenge_04.hpp"
#include "challenge_05.hpp"
#include "challenge_06.hpp"
#include "challenge_07.hpp"
#include "challenge_08.hpp"

#include <hamarr/profiling.hpp>

namespace set_01
{

void run_all()
{
  hmr::profile::benchmark(set_01::challenge_01::run);
  hmr::profile::benchmark(set_01::challenge_02::run);
  hmr::profile::benchmark(set_01::challenge_03::run);
  hmr::profile::benchmark(set_01::challenge_04::run);
  hmr::profile::benchmark(set_01::challenge_05::run);
  hmr::profile::benchmark(set_01::challenge_06::run);
  hmr::profile::benchmark(set_01::challenge_07::run);
  hmr::profile::benchmark(set_01::challenge_08::run);
}

} // namespace set_01

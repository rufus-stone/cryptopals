#pragma once

#include <string>

namespace cp
{

auto encrypt_under_random_key_and_mode(const std::string &input) -> std::string;

} // namespace cp

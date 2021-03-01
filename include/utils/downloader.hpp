#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace cp
{

// Read in a file one line at a time, and add each line to a vector
auto file_to_vector(const std::filesystem::path &file_path) -> std::vector<std::string>;

// Read in a file one line at a time, and concatenate all lines together into a single string
auto file_to_string(const std::filesystem::path &file_path) -> std::string;

// Download challenge data and return a std::filesystem::path to the download location
auto download_challenge_data(const std::string &url_string, const std::size_t set_num, const std::size_t chall_num) -> std::filesystem::path;

} // namespace cp

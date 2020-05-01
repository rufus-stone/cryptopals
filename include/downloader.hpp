#pragma once

#include <cpr/cpr.h>

#include <fstream> // For file i/o
#include <filesystem> // For filesystem stuff
#include <cstdlib> // For getting the path to the home directory

#include <string>
#include <vector>

#include "utils.hpp"

namespace cp
{

// Read in a file one line at a time, and add each line to a vector
std::vector<std::string> file_to_vector(const std::filesystem::path &file_path)
{
  if (!std::filesystem::exists(file_path))
  {
    LOG_ERROR("Failed to find file path:" << file_path);
    return std::vector<std::string>{};
  }

  // Open the file
  auto file_in = std::ifstream{file_path, std::ios::binary};

  // Read in a line at a time
  auto line = std::string{};
  auto data = std::vector<std::string>{};
  while (std::getline(file_in, line))
  {
    data.push_back(line);
  }

  // Close the file if necessary - not sure this is needed...
  if (file_in.is_open())
  {
    file_in.close();
  }

  // Abort condition - did we read any lines?
  if (data.empty())
  {
    LOG_ERROR("Failed to read any data from file!");
    return std::vector<std::string>{};
  }

  return data;
}

// Read in a file one line at a time, and concatenate all lines together into a single string
std::string file_to_string(const std::filesystem::path &file_path)
{
  if (!std::filesystem::exists(file_path))
  {
    LOG_ERROR("Failed to find file path:" << file_path);
    return std::string{};
  }

  // Open the file
  auto file_in = std::ifstream{file_path, std::ios::binary};

  // Read in a line at a time
  auto line = std::string{};
  auto data = std::string{};
  while (std::getline(file_in, line))
  {
    data += line;
  }

  // Close the file if necessary - not sure this is needed...
  if (file_in.is_open())
  {
    file_in.close();
  }

  // Abort condition - did we read any lines?
  if (data.empty())
  {
    LOG_ERROR("Failed to read any data from file!");
    return std::string{};
  }

  return data;
}


std::filesystem::path download_challenge_data(const std::string &url_string, const std::size_t set_num, const std::size_t chall_num)
{
  auto home_path_ptr = std::getenv("HOME");

  // Abort condition - did we find the user's home directory?
  if (home_path_ptr == nullptr)
  {
    LOG_ERROR("Couldn't get path to home directory!");
    return std::filesystem::path{};
  }

  // Build path to the Desktop folder
  const auto home_path = std::string{home_path_ptr};
  auto desktop_path = std::filesystem::path{home_path + "/Desktop"};

  // Abort condition - is the Desktop folder where we expect it to be?
  if (!std::filesystem::exists(desktop_path) || !std::filesystem::is_directory(desktop_path))
  {
    LOG_ERROR("Couldn't find the Desktop folder!");
    return std::filesystem::path{};
  }

  // Build path to the given set folder
  auto set_dir_path = std::filesystem::path{desktop_path / "challenges" / std::to_string(set_num)};

  // If the given set folder doesn't exist, create it on the Desktop
  if (!std::filesystem::exists(set_dir_path) || !std::filesystem::is_directory(set_dir_path))
  {
    LOG_INFO("Directory doesn't exist! Creating it now...");
    std::filesystem::create_directories(set_dir_path);
  } else
  {
    LOG_INFO("Directory already exists.");
  }

  // Build path to the data file for the challenge
  const auto set_challenge_path = set_dir_path / (std::to_string(chall_num) + ".challenge");

  // Check if we've already downloaded this challenge's data file
  if (!std::filesystem::exists(set_challenge_path) || (std::filesystem::is_regular_file(set_challenge_path) && std::filesystem::is_empty(set_challenge_path)))
  {
    LOG_INFO("Downloading challenge data file...");

    // Download the file - disable SSL verification as otherw we get the error: "SSL certificate problem: unable to get local issuer certificate"
    auto result = cpr::Get(cpr::Url{url_string}, cpr::VerifySsl{false});

    LOG_INFO("Download status: " << result.status_code);

    // Abort condition - did we actually download anything?
    if (result.status_code != 200 || result.text.empty())
    {
      LOG_ERROR("Failed to download challenge data!");
      return std::filesystem::path{};
    }

    // Save the file to disk
    auto file_out = std::ofstream{set_challenge_path, std::ios::binary};
    file_out << result.text;
    file_out.close();

    return set_challenge_path;
    
  } else
  {
    LOG_INFO("Already downloaded challenge data file...\n");
    return set_challenge_path;
  }
}

} // namespace cp

#include "utils/downloader.hpp"

#include <fstream> // For file i/o
#include <filesystem> // For filesystem stuff
#include <cstdlib> // For getting the path to the home directory
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

#include <cpr/cpr.h>

namespace cp
{

// Read in a file one line at a time, and add each line to a vector
auto file_to_vector(std::filesystem::path const &file_path) -> std::vector<std::string>
{
  if (!std::filesystem::exists(file_path))
  {
    spdlog::error("Failed to find file path: {}", file_path.string());
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
    spdlog::error("Failed to read any data from file!");
    return std::vector<std::string>{};
  }

  return data;
}

// Read in a file one line at a time, and concatenate all lines together into a single string
auto file_to_string(std::filesystem::path const &file_path) -> std::string
{
  if (!std::filesystem::exists(file_path))
  {
    spdlog::error("Failed to find file path: {}", file_path.string());
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
    spdlog::error("Failed to read any data from file!");
    return std::string{};
  }

  return data;
}


// Download challenge data and return a std::filesystem::path to the download location
auto download_challenge_data(std::string const &url_string, std::size_t const set_num, std::size_t const chall_num) -> std::filesystem::path
{
  char *home_path_ptr = std::getenv("HOME");

  // Abort condition - did we find the user's home directory?
  if (home_path_ptr == nullptr)
  {
    spdlog::error("Couldn't get path to home directory!");
    return std::filesystem::path{};
  }

  // Build path to the Desktop folder
  std::string const home_path = std::string{home_path_ptr};
  auto const desktop_path = std::filesystem::path{home_path + "/Desktop"};

  // Abort condition - is the Desktop folder where we expect it to be?
  if (!std::filesystem::exists(desktop_path) || !std::filesystem::is_directory(desktop_path))
  {
    spdlog::error("Couldn't find the Desktop folder!");
    return std::filesystem::path{};
  }

  // Build path to the given set folder
  auto const set_dir_path = std::filesystem::path{desktop_path / "challenges" / std::to_string(set_num)};

  // If the given set folder doesn't exist, create it on the Desktop
  if (!std::filesystem::exists(set_dir_path) || !std::filesystem::is_directory(set_dir_path))
  {
    spdlog::warn("Directory doesn't exist! Creating it now...");
    std::filesystem::create_directories(set_dir_path);
  } else
  {
    spdlog::info("Directory already exists.");
  }

  // Build path to the data file for the challenge
  auto const set_challenge_path = set_dir_path / (std::to_string(chall_num) + ".challenge");

  // Check if we've already downloaded this challenge's data file
  if (!std::filesystem::exists(set_challenge_path) || (std::filesystem::is_regular_file(set_challenge_path) && std::filesystem::is_empty(set_challenge_path)))
  {
    spdlog::info("Downloading challenge data file...");

    // Download the file - disable SSL verification as otherw we get the error: "SSL certificate problem: unable to get local issuer certificate"
    cpr::Response const result = cpr::Get(cpr::Url{url_string}, cpr::VerifySsl{false});

    spdlog::info("Download status: {}", result.status_code);

    // Abort condition - did we actually download anything?
    if (result.status_code != 200 || result.text.empty())
    {
      spdlog::error("Failed to download challenge data!");
      return std::filesystem::path{};
    }

    // Save the file to disk
    auto file_out = std::ofstream{set_challenge_path, std::ios::binary};
    file_out << result.text;
    file_out.close();

    return set_challenge_path;

  } else
  {
    spdlog::info("Already downloaded challenge data file...");
    return set_challenge_path;
  }
}

} // namespace cp

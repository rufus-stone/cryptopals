cmake_minimum_required(VERSION 3.15...3.18)

project(
  cryptopals_challenges
  VERSION 0.12.0
  DESCRIPTION "Solutions to the cryptopals challenges"
  LANGUAGES CXX)

add_executable(${PROJECT_NAME} main.cpp)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE -Werror -Wall -Wextra
                                               -Wold-style-cast -Wpedantic)

# Download the CPR library
include(FetchContent)
FetchContent_Declare(
  cpr
  GIT_REPOSITORY https://github.com/whoshuu/cpr.git
  GIT_TAG 5e87cb5f45ac99858f0286dc1c35a6cd27c3bcb9) # the commit hash for 1.5.1
FetchContent_MakeAvailable(cpr)

# include_directories(src) Add the include directory to the target
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Find the Hamarr library
find_package(hamarr CONFIG REQUIRED)

# We use spdlog for logging
find_package(spdlog REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE hamarr::hamarr spdlog::spdlog
                                              cpr::cpr)

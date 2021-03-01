cmake_minimum_required(VERSION 3.15...3.18)

# +---------------+
# | Project setup |
# +---------------+

project(
  cryptopals_challenges
  VERSION 0.13.0
  DESCRIPTION "Solutions to the cryptopals challenges"
  LANGUAGES CXX)

# Create our executable
add_executable(
  ${PROJECT_NAME}
  # Main
  src/main.cpp
  # Utils
  src/utils/crypto.cpp
  src/utils/downloader.cpp
  # Set 01
  src/set_01/challenge_01.cpp
  src/set_01/challenge_02.cpp
  src/set_01/challenge_03.cpp
  src/set_01/challenge_04.cpp
  src/set_01/challenge_05.cpp
  src/set_01/challenge_06.cpp
  src/set_01/challenge_07.cpp
  src/set_01/challenge_08.cpp
  # Set 02
  src/set_02/challenge_09.cpp
  src/set_02/challenge_10.cpp
  src/set_02/challenge_11.cpp
  src/set_02/challenge_12.cpp
  src/set_02/challenge_13.cpp)

# We're using C++17
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

# Set compiler warnings
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -W4 -WX)
else()
  target_compile_options(${PROJECT_NAME} PRIVATE -Werror -Wall -Wextra
                                                 -Wold-style-cast -Wpedantic)
endif()

# +--------------+
# | Dependencies |
# +--------------+

# Conan script
include(${PROJECT_SOURCE_DIR}/cmake/conan.cmake)

# Pull in the conan dependencies
conan_cmake_run(
  REQUIRES
  cpr/1.5.2
  spdlog/1.8.2
  BASIC_SETUP
  CMAKE_TARGETS
  BUILD
  missing)

# include_directories(src) Add the include directory to the target
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Find the Hamarr library
find_package(hamarr CONFIG REQUIRED)

# Link libraries to executable
target_link_libraries(${PROJECT_NAME} PRIVATE hamarr::hamarr CONAN_PKG::spdlog
                                              CONAN_PKG::cpr)

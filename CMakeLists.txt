cmake_minimum_required(VERSION 3.18...3.20)

# +---------------+
# | Project setup |
# +---------------+

project(
  cryptopals_challenges
  VERSION 0.14.1
  DESCRIPTION "Solutions to the cryptopals challenges"
  LANGUAGES CXX)

# Create our executable
add_executable(${PROJECT_NAME})

# Add the source files to the target
target_sources(
  ${PROJECT_NAME}
  PRIVATE # Main
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
          src/set_02/challenge_13.cpp
          src/set_02/challenge_14.cpp
          src/set_02/challenge_15.cpp
          src/set_02/challenge_16.cpp)

# We're using C++17
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

# Set include dirs
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${PROJECT_SOURCE_DIR}/include)

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

# Download Conan script if needed
if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
  message(
    "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
  file(
    DOWNLOAD
    "https://raw.githubusercontent.com/conan-io/cmake-conan/v0.16.1/conan.cmake"
    "${CMAKE_BINARY_DIR}/conan.cmake"
    EXPECTED_HASH
      SHA256=396e16d0f5eabdc6a14afddbcfff62a54a7ee75c6da23f32f7a31bc85db23484
    TLS_VERIFY ON)
endif()

# Load the Conan script
include(${CMAKE_BINARY_DIR}/conan.cmake)

# Configure Conan to grab our dependencies
conan_cmake_configure(REQUIRES cpr/1.6.2 spdlog/1.8.5 GENERATORS
                      cmake_find_package)

# Do some settings stuff??
conan_cmake_autodetect(settings)

# Install the dependencies
conan_cmake_install(
  PATH_OR_REFERENCE
  .
  BUILD
  missing
  REMOTE
  conan-center
  SETTINGS
  ${settings})

# This is necessary otherwise find_package() doesn't look in the right place for
# the conan dependencies
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

# Find the Conan dependencies
find_package(spdlog REQUIRED)
find_package(cpr REQUIRED)

# Find the Hamarr library
find_package(hamarr CONFIG REQUIRED)

# Link libraries to executable
target_link_libraries(${PROJECT_NAME} PRIVATE hamarr::hamarr spdlog::spdlog
                                              cpr::cpr)

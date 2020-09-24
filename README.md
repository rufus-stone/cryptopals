# cryptopals

Working through the cryptopals challenges

## Dependencies

- [hamarr](https://github.com/rufus-stone/hamarr) for data manipulation
- [spdlog](https://github.com/gabime/spdlog) for logging
- [cpr](https://github.com/whoshuu/cpr) for downloading the challenge data

CMake expects versions between 3.15 to 3.18

Currently, both hamarr and spdlog must already be installed on your system, but cpr is downloaded for you by CMake

This is has only been tested on Linux
- TODO: Test cross-platform

## Build and Run

```sh
git clone git@github.com:rufus-stone/cryptopals.git

cd cryptopals

# Get CMake to create a new build directory
cmake -S . -B build

# Build the executable
cmake --build build

# Run to see the tests pass
./build/cryptopals-challenges

```

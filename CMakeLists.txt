cmake_minimum_required(VERSION 3.0.0)
project(cryptopals_challenges VERSION 0.1.0)

include(CTest)
enable_testing()

add_subdirectory(cpr)

include_directories(src)
include_directories(include)
include_directories(${CPR_INCLUDE_DIRS})
include_directories(utils/include)

add_executable(cryptopals_challenges main.cpp)

target_link_libraries(cryptopals_challenges ${CPR_LIBRARIES})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

target_compile_features(cryptopals_challenges PUBLIC cxx_std_17)
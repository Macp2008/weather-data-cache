cmake_minimum_required(VERSION 3.22)
project(weather_data_cache CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fstack-protector-strong
    -Wall
    -Wno-unused-parameter
)

add_link_options(
    -Wl,--gc-sections
    -Wl,-z,relro
    -Wl,-z,now
)

# Construir libcerebro.so incluyendo el stub de log
add_library(cerebro SHARED
    src/cerebro_core.cpp
    src/log_stub.cpp
)

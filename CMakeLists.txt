cmake_minimum_required(VERSION 3.22)
project(weather_data_cache CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flags de optimización y obfuscación ligera
add_compile_options(
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fstack-protector-strong
)

add_link_options(
    -Wl,--gc-sections
    -Wl,-z,relro
    -Wl,-z,now
)

# Librería compartida del cerebro
add_library(cerebro SHARED
    src/cerebro_core.cpp
    src/loader.cpp
    src/jni_bridge.cpp
)

# Dependencias del sistema
find_library(log-lib log)
target_link_libraries(cerebro ${log-lib})

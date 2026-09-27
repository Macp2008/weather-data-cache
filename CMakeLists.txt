cmake_minimum_required(VERSION 3.22.1)
project("cerebro" CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# === Librería principal ===
add_library(cerebro SHARED src/cerebro_core.cpp)

# === FLAGS DE SEGURIDAD - CAPA 4 ===
target_compile_options(cerebro PRIVATE
    -O3
    -fvisibility=hidden
    -fno-rtti
    -fno-exceptions
    -ffunction-sections
    -fdata-sections
    -fomit-frame-pointer
)

target_link_options(cerebro PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
)

target_link_libraries(cerebro log)

cmake_minimum_required(VERSION 3.20)
project(AIBridge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_SYSTEM_VERSION 10.0)

# Prevent linking against user-mode CRT
set(CMAKE_C_FLAGS "/kernel /GS- /Gz /Zl /wd4995 /wd4996")

add_library(aibridge SHARED aibridge.c)

target_link_libraries(aibridge
    ntoskrnl.lib
    wdfkmdf.lib
    ntstrsafe.lib
    hal.lib
)

# Driver entry point (no CRT)
set_target_properties(aibridge PROPERTIES
    LINK_FLAGS "/DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry"
)

install(TARGETS aibridge DESTINATION .)
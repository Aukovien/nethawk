cmake_minimum_required(VERSION 3.10)
project(NetHawk VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find packages
find_package(Qt5 COMPONENTS Widgets Network REQUIRED)
find_package(Threads REQUIRED)

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/PacketCapture.cpp
)

# Add executable
add_executable(nethawk ${SOURCES})

# Include directories
target_include_directories(nethawk PRIVATE 
    ${Qt5Widgets_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(nethawk 
    Qt5::Widgets 
    Qt5::Network 
    ${PCAP_LIBRARIES}
    Threads::Threads
)

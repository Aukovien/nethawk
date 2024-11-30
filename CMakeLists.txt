cmake_minimum_required(VERSION 3.10)
project(NetHawk VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 COMPONENTS Widgets Network REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(Threads REQUIRED)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/PacketCapture.cpp
)

add_executable(nethawk ${SOURCES})

target_link_libraries(nethawk 
    Qt5::Widgets 
    Qt5::Network 
    pcap 
    Threads::Threads
)
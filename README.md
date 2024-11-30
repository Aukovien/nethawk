# nethawk

nethawk is a network monitoring tool.

### compiling

to compile and run this code, you'll need the following or its equivalent depending on your distro:
- qt5-default
- qtcreator
- libpcap-dev
- cmake
- build-essential


create a build directory.
```bash
mkdir build
cd build
```

configure and build. 
```bash
cmake ..
make
```

you may need to run it with sudo.
```bash
sudo ./nethawk
```

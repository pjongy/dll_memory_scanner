# Windows DLL with Go

This project demonstrates how to create a Windows DLL in Go that opens a console with an interactive command shell when loaded.

## Building on Windows

To build the DLL directly on Windows:

```bash
go build -buildmode=c-shared -o mymodule.dll
```

This will create a Windows DLL that can be loaded by any application. No additional tools are required as Go natively supports Windows APIs.

## Cross-compiling from Linux

To build a Windows DLL from Linux, you'll need to install the MinGW cross-compiler:

### Installing MinGW

For Debian/Ubuntu:
```bash
sudo apt-get install gcc-mingw-w64
```

For Fedora:
```bash
sudo dnf install mingw64-gcc
```

### Building the DLL

Once MinGW is installed, use the following command to cross-compile:

```bash
CC=x86_64-w64-mingw32-gcc \
GOOS=windows \
GOARCH=amd64 \
CGO_ENABLED=1 \
go build -buildmode=c-shared -o mymodule.dll
```

This will generate a Windows-compatible DLL that can be loaded on a Windows system.

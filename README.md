# NTTTCP

A Windows network throughput benchmark tool.

## Building

[![Build](https://github.com/microsoft/ntttcp/actions/workflows/build.yml/badge.svg)](https://github.com/microsoft/ntttcp/actions/workflows/build.yml)

In a command prompt in the `src` directory run the following:

> **Note** - Cmake 3.15 at minimum is required.

```
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

The binary will be at `build/Release/ntttcp.exe`

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

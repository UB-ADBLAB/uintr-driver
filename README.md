# Intel User Interrupts (UINTR) Linux Driver

A Linux kernel module that provides support for Intel's User Interrupts (UINTR)
feature, allow user-space applications to send and receive interrupts directly
without kernel intervention.

## Prerequisites

- Linux kernel headers and build tools
- Nix package manager (optional, for development environment)

## Building

### Using Make directly

```bash
# Set the kernel directory if not compiling for the running kernel
export KERNELDIR=/path/to/kernel/headers

# Build the module
make

# Clean build artifacts
make clean
```

### Using Nix Development Environment

This project includes a Nix flake for setting up a consistent development
environment:

```bash
# Enter the development shell
nix develop

# Build the module (KERNELDIR is automatically set)
make
```

## Installation

```bash
# Build module & user-space library
make

# Install user-space library
sudo make install

# Update dynamic linker cache
sudo ldconfig

# Load the kernel module
sudo make load
```

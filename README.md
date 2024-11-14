# Intel User Interrupts (UINTR) Linux Driver

A Linux kernel module that provides support for Intel's User Interrupts (UINTR) feature.

## Prerequisites

- Linux kernel headers and build tools
- Nix package manager (optional, for development environment)

## Building

### Using Make directly

```bash
# Set the kernel directory if not using the running kernel
export KERNELDIR=/path/to/kernel/headers

# Build the module
make

# Clean build artifacts
make clean
```

### Using Nix Development Environment

This project includes a Nix flake for setting up a consistent development environment:

```bash
# Enter the development shell
nix develop

# Build the module (KERNELDIR is automatically set)
make
```

## Installation

```bash
# Load the module
sudo insmod intel-uintr.ko

# Verify the module is loaded
lsmod | grep intel-uintr

# View kernel logs for driver status
dmesg | grep UINTR
```

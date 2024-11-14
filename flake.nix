{
  description = "Intel UINTR Linux Driver Development Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # Kernel source and headers
        linuxPackages = pkgs.linuxPackages_6_6;
        kernel = linuxPackages.kernel;

        # Build dependencies
        nativeBuildInputs = with pkgs; [
          pkg-config
          gcc
          gnumake
          bc
          bison
          flex
          openssl
          perl
          elfutils

          # Development tools
          gdb
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          # Kernel development specific
          linuxPackages.kernel.dev
          ncurses # For kernel menuconfig

          # Additional tools
          usbutils
          pciutils

          # Testing tools
          qemu
        ];

        uintrModule = pkgs.stdenv.mkDerivation {
          name = "uintr-build-check";
          src = self;

          nativeBuildInputs = nativeBuildInputs;
          buildInputs = buildInputs;

          buildPhase = ''
            make KERNELDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build
          '';

          installPhase = ''
            mkdir -p $out/lib/modules
            cp ./intel-uintr.ko $out/lib/modules/
          '';
        };

      in
      {

        packages.default = uintrModule;
        checks.x86_64-linux = uintrModule;

        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;

          # Environment variables
          KERNELDIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
          KERNELVERSION = kernel.modDirVersion;

          shellHook = ''
            echo "Setting up UINTR module development environment..."
            echo "Kernel version: $KERNELVERSION"
            echo "Kernel build directory: $KERNEL_DIR"
          '';

        };
      }
    );
}

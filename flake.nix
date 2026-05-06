{
  description = "Environment for reverse engineering";

  nixConfig = {
    extra-substituters = [ "https://pwndbg.cachix.org" ];
    extra-trusted-public-keys = [ "pwndbg.cachix.org-1:HhtIpP7j73SnuzLgobqqa8LVTng5Qi36sQtNt79cD3k=" ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    pwndbg.url = "github:pwndbg/pwndbg";
  };

  outputs =
    inputs@{ flake-parts, pwndbg, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, system, ... }:
        {
          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.gdb

              # Unified Python env: pwntools (exploit dev), capstone (disassembly),
              # pyelftools (ELF parsing), ropgadget (gadget search for iter 2).
              (pkgs.python3.withPackages (ps: with ps; [
                pwntools
                capstone
                pyelftools
                ropgadget
              ]))

              pwndbg.packages.${system}.pwndbg
            ];

            # Disable all Nix CC wrapper hardening flags
            hardeningDisable = [ "all" ];

            # Explicitly disable all security features for vulnerable binaries.
            # hardeningDisable only stops Nix from *adding* flags; these counter
            # GCC/ld built-in defaults so `checksec` shows everything disabled.
            shellHook = ''
              export NIX_CFLAGS_COMPILE="''${NIX_CFLAGS_COMPILE:-} -fno-stack-protector -fcf-protection=none -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-pie"
              export NIX_LDFLAGS="''${NIX_LDFLAGS:-} --no-pie -z execstack -z norelro"
            '';
          };
        };
    };
}

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
              pwndbg.packages.${system}.pwndbg
            ];
          };
        };
    };
}

{
  description = "fractal-trigger — minimal root-privileged D-Bus executor for Fractal Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      mkPackage = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "fractal-trigger";
        version = "0.1.0";
        src = self;
        cargoLock.lockFile = ./Cargo.lock;
        meta.mainProgram = "fractal-trigger";
      };

      linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      overlays.default = final: prev: { fractal-trigger = mkPackage final; };
      nixosModules.default = import ./nix/module.nix;

      checks = nixpkgs.lib.genAttrs linuxSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          vm = import ./nix/vm-test.nix {
            inherit pkgs;
            module = self.nixosModules.default;
            package = mkPackage pkgs;
          };
        });
    }
    // flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = mkPackage pkgs;
      });
}

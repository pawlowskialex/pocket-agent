{
  description = "SSH agent for macOS that keeps the private keys on your phone";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        pocket-agent = pkgs.callPackage ./package.nix { };
        default = pocket-agent;
      });

      overlays.default = final: _prev: { pocket-agent = final.callPackage ./package.nix { }; };

      darwinModules = rec {
        pocket-agent = import ./module.nix { inherit self; };
        default = pocket-agent;
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.nodejs
          ];
        };
      });
    };
}

{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "pocket-agent";
  version = "0.4.0";

  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: _type:
      let
        base = baseNameOf path;
      in
      !(lib.hasSuffix ".nix" base || base == "test" || base == "README.md" || base == "flake.lock" || base == "target");
  };

  cargoHash = "sha256-/5dIVvGEdlesl9ip3C7j6y3vsyAXplCgzgqkk4nOnvw=";

  # Tests need ssh-agent, ssh-keygen and node; see test/.
  doCheck = false;

  meta = {
    description = "SSH agent for macOS that keeps the private keys on your phone";
    homepage = "https://github.com/pawlowskialex/pocket-agent";
    mainProgram = "pocket-agent";
    platforms = lib.platforms.darwin;
  };
}

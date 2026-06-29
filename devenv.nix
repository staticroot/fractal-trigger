{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    channel = "stable";
  };

  packages = [ pkgs.git ];

  tasks = {
    "trigger:build".exec = "cargo build";
    "trigger:test".exec = "cargo test";
    "trigger:clippy".exec = "cargo clippy --all-targets -- -D warnings";
    "trigger:run-vm-test".exec = "nix build .#checks.aarch64-linux.vm -L";
    "trigger:run-vm".exec = "nix run .#vm";
  };
}

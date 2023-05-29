{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # nativeBuildInputs is usually what you want -- tools you need to run
  nativeBuildInputs = with pkgs; [
    gdb
    lldb
    postgresql
    sqlite
    diesel-cli
    openssl
    pkg-config
  ];
}
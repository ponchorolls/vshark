{
  description = "A high-performance network chat-like TUI";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rust-analyzer
            libpcap
            wireshark-cli # Provides dumpcap
            pkg-config
          ];

          shellHook = ''
            export LD_LIBRARY_PATH=${pkgs.libpcap}/lib:$LD_LIBRARY_PATH
            echo "Network TUI Dev Environment Loaded"
          '';
        };
      });
}

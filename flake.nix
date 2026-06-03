{
  description = "pops — reproducible dev shell for building the WASM bindings (ts/build-wasm.sh) and running the Next.js demo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Rust 1.95 (matches rust-toolchain.toml) plus the wasm target the
        # bindings compile to.
        rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override {
          targets = [ "wasm32-unknown-unknown" ];
        };

        # The wasm-bindgen CLI MUST equal Cargo.lock's wasm-bindgen (0.2.122),
        # or wasm-pack aborts on a schema-version mismatch. nixpkgs currently
        # ships 0.2.121, so vendor the upstream prebuilt 0.2.122 release binary
        # (the route the ts/README recommends as reliable).
        wasm-bindgen-cli =
          let
            version = "0.2.122";
            triple = {
              "aarch64-darwin" = "aarch64-apple-darwin";
              "x86_64-darwin" = "x86_64-apple-darwin";
              "x86_64-linux" = "x86_64-unknown-linux-musl";
              "aarch64-linux" = "aarch64-unknown-linux-gnu";
            }.${system};
            hashes = {
              "aarch64-darwin" = "sha256-Nr6tyGxcAsURoVLo/CxjhQZGiH6X3JSuBFU2QPg56Ag=";
              "x86_64-darwin" = pkgs.lib.fakeHash;
              "x86_64-linux" = pkgs.lib.fakeHash;
              "aarch64-linux" = pkgs.lib.fakeHash;
            };
          in
          pkgs.stdenvNoCC.mkDerivation {
            pname = "wasm-bindgen-cli";
            inherit version;
            src = pkgs.fetchurl {
              url = "https://github.com/rustwasm/wasm-bindgen/releases/download/${version}/wasm-bindgen-${version}-${triple}.tar.gz";
              hash = hashes.${system};
            };
            sourceRoot = ".";
            nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              find . -maxdepth 2 -type f \( -name 'wasm-bindgen' -o -name 'wasm-bindgen-test-runner' -o -name 'wasm2es6js' \) \
                -exec cp {} $out/bin/ \;
              chmod +x $out/bin/*
              runHook postInstall
            '';
          };

        # Unwrapped LLVM for the secp256k1-sys C -> wasm32 compile (pulled in via
        # cashu under the `wasm` feature). cc-rs reads CC_<target>/AR_<target>.
        # The wrapped darwin clang injects -isysroot / -mmacosx flags that break
        # a freestanding wasm32 target, so point cc-rs at the bare tools.
        llvm = pkgs.llvmPackages;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            wasm-bindgen-cli
            pkgs.wasm-pack
            pkgs.binaryen # wasm-opt (optional shrink step)
            pkgs.nodejs_22
            llvm.clang-unwrapped # clang with the wasm32 backend
            llvm.bintools-unwrapped # provides llvm-ar
          ];

          # secp256k1-sys (cc-rs) per-target compiler + archiver.
          CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
          AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";

          shellHook = ''
            echo "pops devShell:"
            echo "  rustc        $(rustc --version 2>/dev/null | cut -d' ' -f2)"
            echo "  wasm-bindgen $(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)  (Cargo.lock pins 0.2.122)"
            echo "  wasm-pack    $(wasm-pack --version 2>/dev/null | cut -d' ' -f2)"
            echo "  node         $(node --version 2>/dev/null)"
            echo "Build the bindings:  bash ts/build-wasm.sh"
          '';
        };
      });
}

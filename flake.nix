{
  description = "Tilera TILE-Gx processor module for IDA Pro 9.x";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    ida-sdk = {
      url = "github:HexRaysSA/ida-sdk/v9.3";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      ida-sdk,
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.doubles.linux;
      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });
      idaSdkLinuxLibDirs = {
        x86_64-linux = "x64_linux_gcc_64";
      };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        lib.optionalAttrs (idaSdkLinuxLibDirs ? ${system}) (
          let
            idaSdkLibDir = idaSdkLinuxLibDirs.${system};
            idaBaseDefineFlags = [
              "-D__LINUX__"
              "-D__EA64__"
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isx86_64 [
              "-D__X64__"
            ];
            idaIdpDefineFlags = lib.escapeShellArgs (idaBaseDefineFlags ++ [ "-D__IDP__" ]);
            idaPluginDefineFlags = lib.escapeShellArgs idaBaseDefineFlags;

            ida-tilegx = pkgs.stdenv.mkDerivation {
              pname = "ida-tilegx";
              version = "0.1.0";
              src = ./.;

              nativeBuildInputs = [
                pkgs.cargo
                pkgs.rustc
                pkgs.autoPatchelfHook
              ];
              buildInputs = [ pkgs.stdenv.cc.cc.lib ];

              # libida.so is provided by the host IDA process at module load time.
              autoPatchelfIgnoreMissingDeps = [ "libida.so" ];

              dontConfigure = true;

              buildPhase = ''
                runHook preBuild

                export CARGO_HOME="$TMPDIR/cargo"
                cargo build --release --offline

                $CXX -std=c++17 -fPIC -shared -o tilegx.so \
                  ${idaIdpDefineFlags} \
                  -I${ida-sdk}/src/include \
                  src/processor.cpp \
                  target/release/libtilegx_core.a \
                  -L${ida-sdk}/src/lib/${idaSdkLibDir} -lida \
                  -lpthread -ldl -lm

                $CXX -std=c++17 -fPIC -shared -o tilegx_raw.so \
                  ${idaPluginDefineFlags} \
                  -I${ida-sdk}/src/include \
                  src/loader.cpp \
                  target/release/libtilegx_core.a \
                  -L${ida-sdk}/src/lib/${idaSdkLibDir} -lida \
                  -lpthread -ldl -lm

                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                install -Dm755 tilegx.so $out/procs/tilegx.so
                install -Dm755 tilegx_raw.so $out/loaders/tilegx_raw.so
                runHook postInstall
              '';

              meta = {
                description = "Tilera TILE-Gx processor module for IDA Pro 9.x";
                license = pkgs.lib.licenses.mpl20;
                platforms = builtins.attrNames idaSdkLinuxLibDirs;
              };
            };

            ida-tilegx-hexrays-probe = pkgs.stdenv.mkDerivation {
              pname = "ida-tilegx-hexrays-probe";
              version = "0.1.0";
              src = ./.;

              nativeBuildInputs = [ pkgs.autoPatchelfHook ];
              buildInputs = [ pkgs.stdenv.cc.cc.lib ];

              autoPatchelfIgnoreMissingDeps = [ "libida.so" ];

              dontConfigure = true;

              buildPhase = ''
                runHook preBuild

                $CXX -std=c++17 -fPIC -shared -o tilegx_hexrays_probe.so \
                  ${idaPluginDefineFlags} \
                  -I${ida-sdk}/src/include \
                  src/probe.cpp \
                  -L${ida-sdk}/src/lib/${idaSdkLibDir} -lida \
                  -lpthread -ldl -lm

                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                install -Dm755 tilegx_hexrays_probe.so $out/plugins/tilegx_hexrays_probe.so
                runHook postInstall
              '';

              meta = {
                description = "Diagnostic Hex-Rays microcode probe for the TILE-Gx IDA module";
                license = pkgs.lib.licenses.mpl20;
                platforms = builtins.attrNames idaSdkLinuxLibDirs;
              };
            };
          in
          {
            default = ida-tilegx;
            inherit ida-tilegx ida-tilegx-hexrays-probe;
          }
        )
      );

      apps = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          gen = {
            type = "app";
            program = lib.getExe (
              pkgs.writeShellApplication {
                name = "tilegx-gen";
                runtimeInputs = [
                  pkgs.nushell
                  pkgs.clang-tools
                ];
                text = "exec nu isa/tilegx-gen.nu";
              }
            );
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.rust-analyzer
              pkgs.clippy
              (pkgs.rustfmt.override { asNightly = true; })
              pkgs.nushell
              self.formatter.${system}
            ];
            shellHook = ''
              cat > compile_commands.json <<EOF
              [
                {
                  "directory": "$PWD",
                  "command": "c++ -std=c++17 -fPIC -D__LINUX__ -D__EA64__ -D__X64__ -D__IDP__ -I${ida-sdk}/src/include -c src/processor.cpp",
                  "file": "$PWD/src/processor.cpp"
                },
                {
                  "directory": "$PWD",
                  "command": "c++ -std=c++17 -fPIC -D__LINUX__ -D__EA64__ -D__X64__ -I${ida-sdk}/src/include -c src/probe.cpp",
                  "file": "$PWD/src/probe.cpp"
                },
                {
                  "directory": "$PWD",
                  "command": "c++ -std=c++17 -fPIC -D__LINUX__ -D__EA64__ -D__X64__ -I${ida-sdk}/src/include -c src/loader.cpp",
                  "file": "$PWD/src/loader.cpp"
                }
              ]
              EOF
            '';
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.writeShellApplication {
          name = "nix3-fmt-wrapper";
          runtimeInputs = [
            pkgs.cargo
            pkgs.clang-tools
            pkgs.fd
            pkgs.nixfmt
            pkgs.taplo
            (pkgs.rustfmt.override { asNightly = true; })
          ];
          text = ''
            fd "$@" -t f -e nix -x nixfmt '{}'
            fd "$@" -t f -e toml -x taplo fmt '{}'
            fd "$@" -t f -e c -e cpp -e h -e hpp -x clang-format -i '{}'
            cargo fmt
          '';
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          formatting =
            pkgs.runCommand "ida-tilegx-formatting-check"
              {
                nativeBuildInputs = [ self.formatter.${system} ];
              }
              ''
                cp -r --no-preserve=mode ${self} src
                cd src
                export HOME="$TMPDIR"
                nix3-fmt-wrapper
                diff -ru ${self} . || {
                  echo "tree is not formatted. run nix fmt and commit the result." >&2
                  exit 1
                }
                touch "$out"
              '';
        }
      );
    };
}

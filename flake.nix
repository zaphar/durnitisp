{
    inputs = {
        nixpkgs.url = "nixpkgs";
        flake-utils.url = "github:numtide/flake-utils";
        naersk = {
            url = "github:nix-community/naersk";
            inputs.nixpkgs.follows = "nixpkgs";
        };
        flake-compat = { url = "github:edolstra/flake-compat"; flake = false; };
    };

    outputs = {self, flake-utils, naersk, ...}:
        flake-utils.lib.eachDefaultSystem (system:
            let
                naersk-lib = naersk.lib."${system}";
            in
            {
                defaultPackage = naersk-lib.buildPackage {
                    pname = "durnitisp";
                    src = ./.;
                };
            }
        );
    
}

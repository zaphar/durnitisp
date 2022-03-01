{
    inputs = {
        flake-utils.url = "github:numtide/flake-utils";
        naersk.url = "github:nix-community/naersk";
    };

    outputs = {self, flake-utils, naersk}:
        flake-utils.lib.eachDefaultSystem (system:
            let
                naersk-lib = naersk.lib."${system}";
            in
            {
                defaultPackage = naersk-lib.buildPackage rec {
                    pname = "kitchen";
                    src = ./.;
                };
            }
        );
    
}
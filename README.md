# RSA D Library

Abandoned, not for lack of quality, but because I believe Rust is a better
language, so I will re-implement this in Rust.

* Author: [Jonathan M. Wilbur](https://jonathan.wilbur.space) <[jonathan@wilbur.space](mailto:jonathan@wilbur.space)>
* Copyright Year: 2018
* License: [MIT License](https://mit-license.org/)
* Version: [0.1.0](https://semver.org/)

## Building and Installing

There are four scripts in `build/scripts` that help you build this library,
in addition to building using `dub`. If you are using Windows, you can build
by running `.\build\scripts\build.ps1` from PowerShell, or `.\build\scripts\build.bat`
from the traditional `cmd` shell. If you are on any POSIX-compliant(-ish)
operating system, such as Linux or Mac OS X, you may build this library using
`./build/scripts/build.sh` or `make -f ./build/scripts/posix.make`. The output
library will be in `./build/libraries`. The command-line tools will be in
`./build/executables`.

For more information on building and installing, see `documentation/install.md`.

## Library Usage

## Command-Line Tools Usage

## Development

- [ ] Source
  - [ ] Concurrent prime generation
- [ ] Testing
  - [ ] Build
    - [ ] Windows
    - [ ] Mac OS X
    - [ ] Linux
- [ ] Documentation
  - [ ] Create the `man` page for `create-rsakey`

## See Also

## Contact Me

If you would like to suggest fixes or improvements on this library, please just
[leave an issue on this GitHub page](https://github.com/JonathanWilbur/rsa-d/issues). If you would like to contact me for other reasons,
please email me at [jonathan@wilbur.space](mailto:jonathan@wilbur.space)
([My GPG Key](https://jonathan.wilbur.space/downloads/jonathan@wilbur.space.gpg.pub))
([My TLS Certificate](https://jonathan.wilbur.space/downloads/jonathan@wilbur.space.chain.pem)). :boar:
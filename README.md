# Symciph

[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![symciph](https://github.com/orlowskilp/symciph/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/orlowskilp/symciph/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/gh/orlowskilp/symciph/graph/badge.svg?token=4K55PNADAF)](https://codecov.io/gh/orlowskilp/symciph)

Simple symmetric encryption utility. This is project is meant for educational purposes only and,
specifically, must not be used in production. The code is not, and will not, be audited.

## Getting started

The suggested method is to build the `symciph` in a container, to avoid headaches with dependencies.
You can opt to build it in your environment, however this will require you to install the entire
Rust toolchain.

### Docker container

Build the container image as follows:

```bash
docker build -t orlowskilp/symciph .
```

After the container image is built, use the following command to see whether everything works well:

```bash
docker run orlowskilp/symciph --help
```

In order to access your system's file system, you're going to need to mount a local directory to
the container. You can bind-mount the current working directory to keep things simple:

```bash
docker run --mount type=bind,src="$(pwd)",target=/tmp orlowskilp/symciph -g des /tmp/des.key
```

This will generate `des.key` file, which can be used as a key for DES encryption scheme (which was
broken in the 80s). Note that the target directory is set to `/tmp` and the output directory is
also pointing to `/tmp`. This will hold true to both input and output files, as you're binding
the current directory, `$(pwd)`, to target directory `/tmp` in the container image.

### Local build

Please refer to `.devcontainer/Dockerfile` for suggestions on how to install the toolchain on your
system.

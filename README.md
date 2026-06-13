[![ci](https://github.com/tillitis/tkey-device-signer/actions/workflows/ci.yaml/badge.svg?branch=main&event=push)](https://github.com/tillitis/tkey-device-signer/actions/workflows/ci.yaml)

# Tillitis TKey Signer


## Device applications

Two signer applications are provided, both with the same protocol. Both sign messages up to 4 KB.

See [Release notes](RELEASE.md).


### Ed25519 signer application

The TKey `tk1 sign` device application is an ed25519 signing tool.
The ed25519 public keys are 32B and signatures 64B (both fit into a
a single protocol chunk).

It is, for instance, used by the
[tkey-ssh-agent](https://github.com/tillitis/tkey-ssh-agent) for SSH
authentication and by
[tkey-sign](https://github.com/tillitis/tkey-sign-cli) for doing
digital signatures of files.

### ML-DSA-44 signer application

The `tk1 mlds` device application is a ML-DSA-44 signing tool. The ML-DSA-44 public keys are 1312B and the signatures 2420B (11 and 21 protocol chunks respectively).

## Client Go package

We provide a Go package to use with `signer`:

- https://github.com/tillitis/tkeysign [![Go Reference](https://pkg.go.dev/badge/github.com/tillitis/tkeysign.svg)](https://pkg.go.dev/github.com/tillitis/tkeysign)

## Signer application protocol

`signer` has a simple application protocol on top of the [TKey Framing
Protocol](https://dev.tillitis.se/protocol/#framing-protocol).

The protocol state machine handling this protocol is documented in
[the implementation notes](docs/implementation-notes.md).

The protocol has the following requests and responses:

| *command*               | *Function*                       | *FP length* | *code* | *data*            | *response*              |
|-------------------------|----------------------------------|-------------|--------|-------------------|-------------------------|
| `CMD_GET_PUBKEY`        | Get the public key (legacy)      | 1 B         | 0x01   | none              | `RSP_GET_PUBKEY`        |
| `CMD_SET_SIZE`          | Set size of message to be signed | 32 B        | 0x03   | size as 32 bit LE | `RSP_SET_SIZE`          |
| `CMD_LOAD_DATA`         | Load a chunk of message          | 128 B       | 0x05   | 127 B null-padded | `RSP_LOAD_DATA`         |
| `CMD_GET_SIG`           | Trigger signing                  | 1 B         | 0x07   | none              | `RSP_GET_SIG`           |
| `CMD_GET_NAMEVERSION`   | Identify version of app          | 1 B         | 0x09   | none              | `RSP_GET_NAMEVERSION`   |
| `CMD_GET_FIRMWARE_HASH` | Ask for digest of firmware       | 32 B        | 0x0b   | size as 32 bit LE | `RSP_GET_FIRMWARE_HASH` |
| `CMD_GET_PUBKEY_CHUNK`  | Get pubkey chunk                 | 4 B         | 0x11   | 1 B chunk index   | `RSP_GET_PUBKEY_CHUNK`  |
| `CMD_GET_SIG_CHUNK`     | Get sig chunk                    | 4 B         | 0x13   | 1 B chunk index   | `RSP_GET_SIG_CHUNK`     |

| *response*              | *FP length* | *code* | *data*                             |
|-------------------------|-------------|--------|------------------------------------|
| `RSP_GET_PUBKEY`        | 128 B       | 0x02   | public key (only for keys < 128B)  |
| `RSP_SET_SIZE`          | 4 B         | 0x04   | 1 byte status                      |
| `RSP_LOAD_DATA`         | 4 B         | 0x06   | 1 byte status                      |
| `RSP_GET_SIG`           | 128 B       | 0x08   | signature (only for sigs < 128B )  |
| `RSP_GET_NAMEVERSION`   | 32 B        | 0x0a   | 2 * 4 byte name, version 32 bit LE |
| `RSP_GET_FIRMWARE_HASH` | 128 B       | 0x0c   | 1 byte status + 64 bytes digest    |
| `RSP_GET_PUBKEY_CHUNK`  | 128 B       | 0x12   | 1 B chunk index + <=120B key chunk |
| `RSP_GET_SIG_CHUNK`     | 128 B       | 0x14   | 1 B chunk index + <=120B sig chunk |

| *status replies* | *code* |
|------------------|--------|
| OK               | 0      |
| BAD              | 1      |

The ed25519 signer identifies itself with:
- `name0`: "tk1  "
- `name1`: "sign"

The ML-DSA-44 signer identifies itself with:
- `name0`: "tk1  "
- `name1`: "mlds"

Please note that `signer` also replies with a `NOK` Framing Protocol
response status if the endpoint field in the FP header is meant for
the firmware (endpoint = `DST_FW`). This is recommended for
well-behaved device applications so the client side can probe for the
firmware.

Typical use by a client application:

1. Probe for firmware by sending firmware's `GET_NAME_VERSION` with FP
   header endpoint = `DST_FW`.
2. If firmware is found, load `signer`.
3. Upon receiving the device app digest back from firmware, switch to
   start talking the `signer` protocol above.
4. Send `CMD_GET_PUBKEY_CHUNK` iteratively to retrieve the signer's public key (`CMD_GET_PUBKEY` will also work if the key is very small). Caller is expected to know the key size know how many chunks are needed. If the public key is already stored, check against it so it's the expected key.
5. Send `CMD_SET_SIZE` to set the size of the message to sign.
6. Send repeated messages with `CMD_LOAD_DATA` to send the
   entire message.
7. Send `CMD_GET_SIG` to trigger signing. Small keys (ed25519) are returned here as data for backwards compatibility.
8. Send `CMD_GET_SIG_CHUNK` iteratively to retrieve the signature.

**Please note**: The firmware detection mechanism is not by any means
secure. If in doubt a user should always remove the TKey and insert it
again before doing any operation.

## Licenses and SPDX tags

Unless otherwise noted, the project sources are copyright Tillitis AB,
licensed under the terms and conditions of the "BSD-2-Clause" license.
See [LICENSE](LICENSE) for the full license text.

Until Oct 17, 2024, the license was GPL-2.0 Only.

External source code we have imported are isolated in their own
directories. They may be released under other licenses. This is noted
with a similar `LICENSE` file in every directory containing imported
sources.

The project uses single-line references to Unique License Identifiers
as defined by the Linux Foundation's [SPDX project](https://spdx.org/)
on its own source files, but not necessarily imported files. The line
in each individual source file identifies the license applicable to
that file.

The current set of valid, predefined SPDX identifiers can be found on
the SPDX License List at:

https://spdx.org/licenses/

We attempt to follow the [REUSE
specification](https://reuse.software/).

## Building

You have two options for build tools: either you use our OCI image
`ghcr.io/tillitis/tkey-builder` or native tools.

An easy way to build is to use the provided scripts:

- `build.sh` for native tools.
- `build-podman.sh` for use with Podman.

These scripts automatilly clone the [tkey-libs device
libraries](https://github.com/tillitis/tkey-libs) in a directory next
to this one.

If you want to use a pre-built libraries, download the libraries tar
ball from

https://github.com/tillitis/tkey-libs/releases

unpack it, and specify where you unpacked it in `LIBDIR` when
building:

```
make LIBDIR=~/Downloads/tkey-libs-v0.1.2
```

Note that your `lld` might complain if they were built with a
different version. If so, either use the same version the release used
or use podman.

### Building with Podman

On Ubuntu 22.10, running

```
apt install podman rootlesskit slirp4netns
```

should be enough to get you a working Podman setup.

You can then either:

- Use `build-podman.sh` as described above, which clones and builds
  the tkey-libs libraries as well.

- Download [pre-built versions of the tkey-libs
  libraries](https://github.com/tillitis/tkey-libs/releases) and
  define `LIBDIR` to where you unpacked the tkey-libs, something
  like:

  ```
  make LIBDIR=$HOME/Downloads/tkey-libs-v0.1.2 podman
  ```

  Note that `~` expansion doesn't work.

### Building with host tools

To build with native tools you need at least the `clang`, `llvm`,
`lld`, packages installed. Version 15 or later of LLVM/Clang is for
support of our architecture (RV32\_Zmmul). Ubuntu 22.10 (Kinetic) is
known to have this. Please see
[toolchain_setup.md](https://github.com/tillitis/tillitis-key1/blob/main/doc/toolchain_setup.md)
(in the tillitis-key1 repository) for detailed information on the
currently supported build and development environment.

Build everything:

```
$ make
```

If you cloned `tkey-libs` to somewhere else then the default set
`LIBDIR` to the path of the directory.

If your available `objcopy` is anything other than the default
`llvm-objcopy`, then define `OBJCOPY` to whatever they're called on
your system.

### Disabling touch requirement

The `signer` normally requires the TKey to be physically touched for
signing to complete. For special purposes it can be compiled with this
requirement removed by setting the environment variable
`TKEY_SIGNER_APP_NO_TOUCH` to some value when building. Example:

```
$ make TKEY_SIGNER_APP_NO_TOUCH=yesplease
```

Of course this changes the signer app binary and as a consequence the
derived private key and identity will change.

## Running

If you just want to sign a file or experiment with the signer, use the
[tkey-sign](https://github.com/tillitis/tkey-sign-cli) command which
you can also use as an example on how to load and run the signer
device app.

[tkey-ssh-agent](https://github.com/tillitis/tillitis-key1-apps) also
uses this signer app.

Please see the [Developer Handbook](https://dev.tillitis.se/) for [how
to run with QEMU](https://dev.tillitis.se/tools/#qemu-emulator) or
[how to run apps on a
TKey](https://dev.tillitis.se/devapp/#running-tkey-apps).

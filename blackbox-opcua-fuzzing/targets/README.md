# OPC UA Fuzzing targets

This directory holds the target setup for the blackbox fuzzing.
To work with the toolchain, a new implementation needs it's own subdirectory.
The subdirectory then needs to hold a shell script `install.sh` with the executable bit set.
The shell script needs to set up the docker container with everything needed to run an opcua server on port 4840.

The server has to be an executable (i.e. elf file or script with shebang an x bit) and it has to be stored at `/opt/app/target`.
This can be done by copying or linking an executable.
If the file or script needs parameters or has to be executed from another working directory you can use a shell wrapper.
This for example is the target for the node implementation:

```bash
#!/usr/bin/env bash

/usr/bin/node /opt/app/node-opcua/packages/node-opcua-samples/bin/simple_server.js -a localhost -p 4840

exit 0
```

## Source revisions

The Node source checkout uses commit `bc0fd185f4905cd03c83c7a278365424f2b46bac`,
the commit behind the previously selected `v2.47.0` tag. The separately
installed `node-opcua` npm package remains unpinned; the checkout and package
combination has not been validated by a clean build or startup test. A pinned
checkout does not make the target reproducible.

The original open62541 research revision is unknown. Upstream commit
`4eec281656aa7aeafbfe3722db17fadb9eacc663` is a date-based candidate from
before this repository's initial commit, not evidence of the original version.
Both installers select this commit before initializing submodules. A clean
shallow checkout with its recorded submodules built in a disposable container
and its `server_ctt` accepted a TCP connection on port 4840. This did not test
an OPC UA exchange, the TLS installer, or the original experiment.

For the Java v0.2 release archive, an independently downloaded copy had SHA-256
`b17796eb72c10f7e517c96f4713a7e7e5fad3eb099b88fe82bfe9bc879344f56`.
This was not compared with an authenticated upstream checksum and is not yet
enforced. The .NET and Python sources and their runtime dependencies also need
compatible, build-tested revisions.

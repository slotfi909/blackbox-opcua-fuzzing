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

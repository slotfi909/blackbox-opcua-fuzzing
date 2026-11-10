FROM blackbox-fuzzer/baseimage

WORKDIR /opt/app

COPY setup_target_auto.sh /opt/app/

RUN ./setup_target_auto.sh

RUN test -f /opt/app/target && test -x /opt/app/target || \
    { echo 'Target installation must produce a regular executable at /opt/app/target' >&2; exit 1; }

ENTRYPOINT ["/opt/app/fuzz_opcua_server.py"]

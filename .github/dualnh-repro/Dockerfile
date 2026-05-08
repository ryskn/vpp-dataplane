FROM ubuntu:24.04

COPY dualnh.test /usr/local/bin/dualnh.test
RUN chmod 0555 /usr/local/bin/dualnh.test

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dualnh.test"]

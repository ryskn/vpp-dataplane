FROM ubuntu:24.04

COPY srpolicy.test /usr/local/bin/srpolicy.test
RUN chmod 0555 /usr/local/bin/srpolicy.test

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/srpolicy.test"]

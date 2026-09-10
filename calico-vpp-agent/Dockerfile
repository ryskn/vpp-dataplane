FROM ubuntu:22.04

LABEL maintainer="aloaugus@cisco.com"

# socat is not needed by any Calico profile.  It is here for the SRv6 Endpoint
# Context Stage 0 profile, which runs a byte-forwarding proxy in front of the
# VPP binary API socket so that the socket the Cilium agent opens satisfies the
# IF-2 filesystem contract of 00 §4.1 (socket mode 0600, directory mode 0700).
# See docs/srv6ec-stage0.md.
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/*

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

ADD bin/gobgp /bin/gobgp
ADD version /etc/calicovppversion
ADD bin/felix-api-proxy /bin/felix-api-proxy
ADD bin/calico-vpp-agent /bin/calico-vpp-agent
ADD bin/podinterface-lifecycle /bin/podinterface-lifecycle

ENTRYPOINT ["/bin/calico-vpp-agent"]

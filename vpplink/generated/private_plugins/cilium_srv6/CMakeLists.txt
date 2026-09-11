# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# SRv6 Endpoint Context v1 — VPP plugin.
#
# This is an out-of-tree VPP plugin. Build it either by pointing a VPP
# source tree's plugin build at this directory, e.g.
#
#   ln -s <cilium>/vpp/plugins/cilium_srv6 <vpp>/src/plugins/cilium_srv6
#   make build
#
# or with an out-of-tree CMake project that does find_package(VPP) and
# add_subdirectory() on this directory. The directory name must stay
# `cilium_srv6` because the sources and the generated API headers are
# included as <cilium_srv6/...>.

add_vpp_plugin(cilium_srv6
  SOURCES
  cilium_srv6_guard.c
  cilium_srv6_guard_node.c
  cilium_srv6_ifbind.c
  cilium_srv6_context.c
  cilium_srv6_endcilium.c
  cilium_srv6_endcilium_node.c
  cilium_srv6_deliver_node.c
  cilium_srv6_headend.c
  cilium_srv6_ct.c
  cilium_srv6_punt.c
  cilium_srv6_punt_transport.c
  cilium_srv6_classify_node.c
  cilium_srv6_ct_node.c
  cilium_srv6_program_node.c
  cilium_srv6_local_deliver_node.c
  cilium_srv6_encap_node.c
  cilium_srv6_punt_node.c
  cilium_srv6_pmtud.c
  cilium_srv6_pmtud_node.c
  cilium_srv6_counters.c
  cilium_srv6_api.c
  cilium_srv6_cli.c

  MULTIARCH_SOURCES
  cilium_srv6_guard_node.c
  cilium_srv6_endcilium_node.c
  cilium_srv6_deliver_node.c
  cilium_srv6_classify_node.c
  cilium_srv6_ct_node.c
  cilium_srv6_program_node.c
  cilium_srv6_local_deliver_node.c
  cilium_srv6_encap_node.c
  cilium_srv6_punt_node.c
  cilium_srv6_pmtud_node.c

  API_FILES
  cilium_srv6.api

  INSTALL_HEADERS
  cilium_srv6_guard.h
  cilium_srv6_ifbind.h
  cilium_srv6_ifbind_rules.h
  cilium_srv6_context.h
  cilium_srv6_endcilium.h
  cilium_srv6_headend.h
  cilium_srv6_ct.h
  cilium_srv6_ct_fsm.h
  cilium_srv6_parse.h
  cilium_srv6_gparse.h
  cilium_srv6_hparse.h
  cilium_srv6_punt_wire.h
  cilium_srv6_revision.h
  cilium_srv6_pmtud.h
  cilium_srv6_pmtud_parse.h
  cilium_srv6_counters.h
)

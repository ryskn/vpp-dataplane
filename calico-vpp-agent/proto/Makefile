# Regenerate the Go bindings of the vendored PodInterfaceLifecycle proto.
#
# podinterface/podinterface.proto is a snapshot of the canonical file in the
# Cilium repository (see PODINTERFACE_PROTO_SOURCE). Its `go_package` names the
# canonical Cilium import path, so the file can stay byte-identical across both
# repositories; the mapping below redirects the generated code into this
# module instead of editing the proto.

PROTO_IMPORT_PATH := github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/proto/podinterface

.PHONY: proto
proto:
	protoc \
		--proto_path=. \
		--go_out=. --go_opt=paths=source_relative \
		--go_opt=Mpodinterface/podinterface.proto=$(PROTO_IMPORT_PATH) \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--go-grpc_opt=Mpodinterface/podinterface.proto=$(PROTO_IMPORT_PATH) \
		podinterface/podinterface.proto

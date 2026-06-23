// Package v1 defines the EgressPolicy CRD types.
//
// Design notes: see srv6egress/docs/.
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EgressPolicy is the Schema for declaring per-tenant SRv6 egress path steering.
// A namespace/pod selector picks source workloads; matched egress traffic is
// SRv6-steered through the SR Policy resolved from <color, endpoint>, then
// SNAT'd to a per-tenant VIP at the egress gateway. Color follows RFC 9256
// (color = path intent / objective).
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=egp;egpol
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Color",type="integer",JSONPath=".spec.egress.color"
// +kubebuilder:printcolumn:name="Upstream",type="string",JSONPath=".status.upstream"
// +kubebuilder:printcolumn:name="EgressIP",type="string",JSONPath=".status.egressIP"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".status.activeEndpoint"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressPolicySpec   `json:"spec"`
	Status EgressPolicyStatus `json:"status,omitempty"`
}

// EgressPolicyList contains a list of EgressPolicy.
//
// +kubebuilder:object:root=true
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []EgressPolicy `json:"items"`
}

// EgressPolicySpec defines the desired egress steering.
type EgressPolicySpec struct {
	// Selector picks the source workloads this policy applies to.
	Selector Selector `json:"selector"`

	// DestinationCIDRs restricts the policy to traffic destined to these CIDRs.
	// When empty, the policy applies to all off-cluster destinations.
	// Each entry MUST be a valid IPv6 CIDR for v1.
	// +optional
	DestinationCIDRs []string `json:"destinationCIDRs,omitempty"`

	// Egress declares where and how the matched traffic exits the cluster.
	Egress EgressSpec `json:"egress"`
}

// Selector chooses source workloads by namespace and/or pod labels.
// Standard Kubernetes label selector semantics; an empty matchLabels +
// matchExpressions matches everything in the corresponding scope.
type Selector struct {
	// NamespaceSelector picks namespaces by labels. Omitted => all namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector picks pods within the matched namespaces. Omitted => all pods.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
}

// EgressSpec declares the egress endpoint, intent (color), and VIP allocation.
type EgressSpec struct {
	// EndpointSelector selects the egress gateway node. v1 requires
	// exactly one node to match; the controller rejects policies whose
	// selector matches zero or more than one node.
	EndpointSelector EndpointSelector `json:"endpointSelector"`

	// Color is the SR Policy color identifying the path intent (RFC 9256 §2.1).
	// Semantics are operator-defined and resolved by the bgp-controller to a
	// concrete segment list via the controller's color/upstream config.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	Color uint32 `json:"color"`

	// EgressIPPool is the name of the Calico IPPool from which the per-tenant
	// egress VIP is allocated by the controller. The pool SHOULD carry
	// allowedUses: [Tunnel] so IPAM does not hand these addresses to pods.
	EgressIPPool string `json:"egressIPPool"`
}

// EndpointSelector selects the egress gateway node.
type EndpointSelector struct {
	// NodeSelector matches the egress gateway node. v1 enforces a
	// single-node match in the controller.
	NodeSelector *metav1.LabelSelector `json:"nodeSelector"`
}

// EgressPolicyStatus reports the observed state.
type EgressPolicyStatus struct {
	// EgressIP is the per-tenant VIP allocated from EgressIPPool.
	// +optional
	EgressIP string `json:"egressIP,omitempty"`

	// ActiveEndpoint is the node name currently serving this policy.
	// +optional
	ActiveEndpoint string `json:"activeEndpoint,omitempty"`

	// Upstream is the symbolic upstream identifier (from controller config)
	// that Color resolves to (e.g. "isp-a").
	// +optional
	Upstream string `json:"upstream,omitempty"`

	// SRPolicy is the resolved SR Policy (BSID + segment list).
	// +optional
	SRPolicy *SRPolicyStatus `json:"srPolicy,omitempty"`

	// Backbone records the RFC 9252 SRv6 service route announced toward the
	// backbone PE for this policy's VIP. Set only when the policy's upstream is
	// stitched to a backbone (the backbone-stitch capability). Persisted BEFORE
	// the announce so deletion can always rebuild the exact withdraw.
	// +optional
	Backbone *BackboneStatus `json:"backbone,omitempty"`

	// Conditions describe the current state. Standard k8s condition types:
	//   - Ready: the policy is installed and traffic is being steered.
	//   - Degraded: a non-fatal error prevents full operation (e.g. eBGP down).
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SRPolicyStatus describes the SR Policy installed for this EgressPolicy.
type SRPolicyStatus struct {
	// BSID is the Binding SID assigned to this SR Policy.
	// +optional
	BSID string `json:"bsid,omitempty"`

	// Color mirrors spec.egress.color (for convenience in `kubectl get`).
	// +optional
	Color uint32 `json:"color,omitempty"`

	// SegmentList is the SR Policy segment list resolved by the controller.
	// +optional
	SegmentList []string `json:"segmentList,omitempty"`

	// EndpointAddr is the SR Policy endpoint IPv6 address advertised in the SR
	// Policy SAFI NLRI. Persisted so Withdraw can rebuild the exact NLRI key
	// (<distinguisher, color, endpoint>) after a controller restart.
	// +optional
	EndpointAddr string `json:"endpointAddr,omitempty"`
}

// BackboneStatus describes the SRv6 service route (RFC 9252) advertised to
// the backbone for this policy's VIP.
type BackboneStatus struct {
	// Prefix is the advertised VIP prefix (e.g. "2001:db8:e::42/128").
	Prefix string `json:"prefix"`

	// EndSID is the gateway's own End.DT6 SID attached to the advertisement
	// (the SID the backbone uses to SR-reach the VIP).
	EndSID string `json:"endSID"`

	// Color is the backbone Color Extended Community value (cluster color
	// mapped through the controller's backbone colorMap).
	Color uint32 `json:"color"`

	// Upstream names the backbone peering (controller config key) the route
	// was announced on.
	// +optional
	Upstream string `json:"upstream,omitempty"`

	// Nexthop is the next-hop used on the GW-PE session.
	// +optional
	Nexthop string `json:"nexthop,omitempty"`
}

func init() {
	SchemeBuilder.Register(&EgressPolicy{}, &EgressPolicyList{})
}

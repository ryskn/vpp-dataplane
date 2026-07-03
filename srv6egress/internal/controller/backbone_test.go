package controller

import "testing"

// The cluster-return advertiser must be leader-elected so a standby replica
// never mutates the backbone BGP session.
func TestClusterReturnAdvertiser_IsLeaderElected(t *testing.T) {
	if !(&ClusterReturnAdvertiser{}).NeedLeaderElection() {
		t.Fatal("cluster-return advertiser must be leader-elected")
	}
}

// Copyright (C) 2026 Cilium Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpplink

import (
	"strings"
	"testing"
)

// 02 §8.1 rule 1: 1..255 bytes of printable ASCII, rejected rather than
// truncated. The typical value is "64 hex + ':' + ifname", which must fit.
func TestValidateAttachmentID(t *testing.T) {
	typical := strings.Repeat("a", 64) + ":eth0"
	if err := ValidateAttachmentID(typical); err != nil {
		t.Fatalf("the typical 69 byte attachment id was rejected: %v", err)
	}
	if err := ValidateAttachmentID(strings.Repeat("a", AttachmentIDMaxLen)); err != nil {
		t.Fatalf("a %d byte attachment id was rejected: %v", AttachmentIDMaxLen, err)
	}

	for name, attachmentID := range map[string]string{
		"empty":            "",
		"one byte too big": strings.Repeat("a", AttachmentIDMaxLen+1),
		"space":            "container id:eth0",
		"tab":              "container\tid:eth0",
		"newline":          "container:eth0\n",
		"nul":              "container\x00:eth0",
		"del":              "container\x7f:eth0",
		"non ascii":        "cöntainer:eth0",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateAttachmentID(attachmentID); err == nil {
				t.Fatalf("accepted an attachment id that is outside the wire constraint")
			}
		})
	}
}

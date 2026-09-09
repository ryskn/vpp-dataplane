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

package cni

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The publication barrier of 00 §2.12.6 is a property of where the binding is
// published inside AddVppInterface:
//
//	the binding ADD must be the last thing that happens before the interface
//	is reported as created, and it must happen while the cleanup stack that
//	rolls the interface back is still in scope.
//
// AddVppInterface cannot be executed without a live VPP, so no behavioural test
// in this package can observe that placement. These tests read the source
// instead. They are narrow on purpose: they exist because the two ways of
// breaking the barrier — publishing after the function returns, and publishing
// without the cleanup stack — are both invisible to every other test here, and
// both are what the contract singles out as forbidden ("CNI ADD 成功を返した後の
// 非同期 binding 書込みは禁止", completion criteria 1 and 3 of §2.12.9).
func parseNetworkVpp(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "network_vpp.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("cannot parse network_vpp.go: %v", err)
	}
	return fset, file
}

func findFunc(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("cannot find %s in network_vpp.go", name)
	return nil
}

// callsPublish reports whether the expression is a call to publishIfAttachment,
// and with how many arguments.
func callsPublish(expr ast.Expr) (bool, int) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false, 0
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "publishIfAttachment" {
		return false, 0
	}
	return true, len(call.Args)
}

func TestAddVppInterfacePublishesBeforeReportingSuccess(t *testing.T) {
	_, file := parseNetworkVpp(t)
	fn := findFunc(t, file, "AddVppInterface")

	publishIndex := -1
	publishArgs := 0
	successReturnIndex := -1

	for i, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if ok, args := callsPublish(s.Rhs[0]); ok {
					publishIndex = i
					publishArgs = args
				}
			}
		case *ast.ReturnStmt:
			// The success return is the one that hands back the interface
			// index; the failure path returns vpplink.InvalidID.
			if len(s.Results) == 2 {
				if sel, ok := s.Results[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "TunTapSwIfIndex" {
					successReturnIndex = i
				}
			}
		}
	}

	if publishIndex < 0 {
		t.Fatalf("AddVppInterface does not publish the binding on its success path: " +
			"the interface would be reported as created before, or without, the binding ADD being acknowledged")
	}
	if successReturnIndex < 0 {
		t.Fatalf("cannot find the success return of AddVppInterface")
	}
	if publishIndex >= successReturnIndex {
		t.Fatalf("AddVppInterface publishes the binding at statement %d, after its success return at %d",
			publishIndex, successReturnIndex)
	}
	// Exactly one statement may sit between them: the error check that jumps to
	// the rollback. Anything else would run after the binding was published but
	// before the interface is reported, which the fixed ADD order does not have.
	if gap := successReturnIndex - publishIndex; gap != 2 {
		t.Fatalf("%d statements sit between the binding publication and the success return, want exactly 1 (the error check)",
			gap-1)
	}
	if publishArgs != 2 {
		t.Fatalf("the binding publication is called with %d arguments, want 2: "+
			"without the cleanup stack, a failed binding ADD cannot roll the interface back",
			publishArgs)
	}
}

// A binding written after the caller was told the interface exists is exactly
// the asynchronous write 00 §2.12.6 forbids.
func TestBindingIsNeverPublishedAsynchronously(t *testing.T) {
	fset, file := parseNetworkVpp(t)
	ast.Inspect(file, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		ast.Inspect(goStmt, func(inner ast.Node) bool {
			if expr, ok := inner.(ast.Expr); ok {
				if publishes, _ := callsPublish(expr); publishes {
					t.Errorf("%s: the binding is published from a goroutine; "+
						"the ADD ACK is the publication barrier and cannot be asynchronous",
						fset.Position(inner.Pos()))
				}
			}
			return true
		})
		return true
	})
}

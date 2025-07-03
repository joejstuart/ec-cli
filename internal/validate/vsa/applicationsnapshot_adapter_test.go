// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"context"
	"testing"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotVSAOrchestrator_GenerateAndWriteVSA(t *testing.T) {
	// Create test data
	report := applicationsnapshot.Report{
		Snapshot: "test-snapshot",
		Success:  true,
		Components: []applicationsnapshot.Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "component1",
					ContainerImage: "quay.io/test/component1:tag",
				},
				Success: true,
				Successes: []evaluator.Result{
					{Message: "Test rule passed"},
				},
			},
		},
	}

	// Create orchestrator with in-memory filesystem
	fs := afero.NewMemMapFs()
	orchestrator := NewSnapshotVSAOrchestrator(fs, nil)

	// Create a test writer
	writer := &testVSAWriter{}

	// Test GenerateAndWriteVSA
	predicatePath, err := orchestrator.GenerateAndWriteVSA(context.Background(), report, writer)
	require.NoError(t, err)
	assert.NotEmpty(t, predicatePath)
	assert.NotNil(t, writer.lastPredicate)
	assert.True(t, writer.lastPredicate.IsSnapshotVSA())
	assert.Equal(t, "test-snapshot", writer.lastPredicate.GetIdentifier())
}

func TestSnapshotVSAWriter_WritePredicate(t *testing.T) {
	fs := afero.NewMemMapFs()
	writer := NewSnapshotVSAWriter(fs, "vsa-test-", 0o600)

	// Create a test predicate
	predicate := &Predicate{
		ImageRef:     "test-image:tag",
		SnapshotName: "test-snapshot",
	}

	// Test WritePredicate
	predicatePath, err := writer.WritePredicate(context.Background(), predicate)
	require.NoError(t, err)
	assert.Contains(t, predicatePath, "vsa-test-")
	assert.Contains(t, predicatePath, "vsa.json")

	// Verify the file was written
	exists, err := afero.Exists(fs, predicatePath)
	require.NoError(t, err)
	assert.True(t, exists)
}

// testVSAWriter is a test implementation of applicationsnapshot.VSAWriter
type testVSAWriter struct {
	lastPredicate applicationsnapshot.VSAPredicate
}

func (w *testVSAWriter) WritePredicate(ctx context.Context, predicate applicationsnapshot.VSAPredicate) (string, error) {
	w.lastPredicate = predicate
	return "test-predicate.json", nil
}

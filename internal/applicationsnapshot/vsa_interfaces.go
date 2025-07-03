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

package applicationsnapshot

import (
	"context"
)

// VSAPredicate represents a VSA predicate that can be generated from a report
type VSAPredicate interface {
	// GetIdentifier returns the unique identifier for this predicate
	GetIdentifier() string
	// IsSnapshotVSA returns true if this is a snapshot VSA
	IsSnapshotVSA() bool
}

// VSAGenerator generates VSA predicates from application snapshot reports
type VSAGenerator interface {
	// GeneratePredicate creates a VSA predicate from the given report
	GeneratePredicate(ctx context.Context, report Report) (VSAPredicate, error)
}

// VSAWriter writes VSA predicates to files
type VSAWriter interface {
	// WritePredicate writes a predicate to a file and returns the file path
	WritePredicate(ctx context.Context, predicate VSAPredicate) (string, error)
}

// VSAAttestor signs and creates envelopes for VSA predicates
type VSAAttestor interface {
	// AttestPredicate signs a predicate and returns the envelope data
	AttestPredicate(ctx context.Context, predicatePath string) ([]byte, error)
	// WriteEnvelope writes the envelope data to a file and returns the file path
	WriteEnvelope(data []byte) (string, error)
}

// VSAOrchestrator coordinates the full VSA generation and attestation process
type VSAOrchestrator interface {
	// GenerateAndWriteVSA generates a predicate and writes it to a file
	GenerateAndWriteVSA(ctx context.Context, report Report, writer VSAWriter) (string, error)
	// AttestVSA signs and envelopes a VSA predicate
	AttestVSA(ctx context.Context, predicatePath string, report Report) (string, error)
}

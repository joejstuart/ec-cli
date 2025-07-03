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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/spf13/afero"
)

// SnapshotVSAOrchestrator implements applicationsnapshot.VSAOrchestrator
type SnapshotVSAOrchestrator struct {
	fs     afero.Fs
	signer *Signer
}

// NewSnapshotVSAOrchestrator creates a new VSA orchestrator for application snapshots
func NewSnapshotVSAOrchestrator(fs afero.Fs, signer *Signer) applicationsnapshot.VSAOrchestrator {
	return &SnapshotVSAOrchestrator{
		fs:     fs,
		signer: signer,
	}
}

// GenerateAndWriteVSA implements applicationsnapshot.VSAOrchestrator.GenerateAndWriteVSA
func (o *SnapshotVSAOrchestrator) GenerateAndWriteVSA(
	ctx context.Context,
	report applicationsnapshot.Report,
	writer applicationsnapshot.VSAWriter,
) (string, error) {
	// Create a snapshot generator
	generator := NewSnapshotGenerator(report)

	// Generate the predicate
	predicate, err := generator.GeneratePredicate(ctx, applicationsnapshot.Component{})
	if err != nil {
		return "", fmt.Errorf("failed to generate predicate: %w", err)
	}

	// Write the predicate using the provided writer
	predicatePath, err := writer.WritePredicate(ctx, predicate)
	if err != nil {
		return "", fmt.Errorf("failed to write predicate: %w", err)
	}

	return predicatePath, nil
}

// AttestVSA implements applicationsnapshot.VSAOrchestrator.AttestVSA
func (o *SnapshotVSAOrchestrator) AttestVSA(
	ctx context.Context,
	predicatePath string,
	report applicationsnapshot.Report,
) (string, error) {
	if o.signer == nil {
		return "", fmt.Errorf("no signer configured for VSA attestation")
	}

	// Create a snapshot attestor
	attestor := NewSnapshotAttestor(
		predicatePath,
		report.Snapshot,
		calculateSnapshotDigest(report.Components),
		o.signer,
	)

	// Attest the predicate
	envelopeData, err := attestor.AttestPredicate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to attest predicate: %w", err)
	}

	// Write the envelope
	envelopePath, err := attestor.WriteEnvelope(envelopeData)
	if err != nil {
		return "", fmt.Errorf("failed to write envelope: %w", err)
	}

	return envelopePath, nil
}

// SnapshotVSAWriter implements applicationsnapshot.VSAWriter
type SnapshotVSAWriter struct {
	fs            afero.Fs
	tempDirPrefix string
	filePerm      os.FileMode
}

// NewSnapshotVSAWriter creates a new VSA writer for application snapshots
func NewSnapshotVSAWriter(fs afero.Fs, tempDirPrefix string, filePerm os.FileMode) applicationsnapshot.VSAWriter {
	return &SnapshotVSAWriter{
		fs:            fs,
		tempDirPrefix: tempDirPrefix,
		filePerm:      filePerm,
	}
}

// WritePredicate implements applicationsnapshot.VSAWriter.WritePredicate
func (w *SnapshotVSAWriter) WritePredicate(ctx context.Context, predicate applicationsnapshot.VSAPredicate) (string, error) {
	// Create a temporary directory
	tempDir, err := afero.TempDir(w.fs, "", w.tempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Marshal the predicate to JSON
	data, err := json.Marshal(predicate)
	if err != nil {
		return "", fmt.Errorf("failed to marshal predicate: %w", err)
	}

	// Write to file
	filename := filepath.Join(tempDir, "vsa.json")
	err = afero.WriteFile(w.fs, filename, data, w.filePerm)
	if err != nil {
		return "", fmt.Errorf("failed to write predicate file: %w", err)
	}

	return filename, nil
}

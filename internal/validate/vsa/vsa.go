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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/cosign/v2/pkg/oci"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
)

// Predicate represents a Verification Summary Attestation (VSA) predicate.
type Predicate struct {
	ImageRef         string                 `json:"imageRef"`
	ValidationResult string                 `json:"validationResult"`
	Timestamp        string                 `json:"timestamp"`
	Verifier         string                 `json:"verifier"`
	PolicySource     string                 `json:"policySource"`
	Component        map[string]interface{} `json:"component"`
	RuleResults      []evaluator.Result     `json:"ruleResults"`
	// Snapshot-specific fields
	SnapshotName   string `json:"snapshotName,omitempty"`
	ComponentCount int    `json:"componentCount,omitempty"`
	SnapshotDigest string `json:"snapshotDigest,omitempty"`
}

// Generator handles VSA predicate generation
type Generator struct {
	Report applicationsnapshot.Report
}

// NewGenerator creates a new VSA predicate generator
func NewGenerator(report applicationsnapshot.Report) *Generator {
	return &Generator{
		Report: report,
	}
}

// GeneratePredicate creates a Predicate for a validated image/component.
func (g *Generator) GeneratePredicate(ctx context.Context, comp applicationsnapshot.Component) (*Predicate, error) {
	log.Infof("Generating VSA predicate for image: %s", comp.ContainerImage)

	// Compose the component info as a map
	componentInfo := map[string]interface{}{
		"name":           comp.Name,
		"containerImage": comp.ContainerImage,
		"source":         comp.Source,
	}

	// Compose rule results: combine violations, warnings, and successes
	ruleResults := make([]evaluator.Result, 0, len(comp.Violations)+len(comp.Warnings)+len(comp.Successes))
	ruleResults = append(ruleResults, comp.Violations...)
	ruleResults = append(ruleResults, comp.Warnings...)
	ruleResults = append(ruleResults, comp.Successes...)

	validationResult := "failed"
	if comp.Success {
		validationResult = "passed"
	}

	policySource := ""
	if g.Report.Policy.Name != "" {
		policySource = g.Report.Policy.Name
	}

	return &Predicate{
		ImageRef:         comp.ContainerImage,
		ValidationResult: validationResult,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "ec-cli",
		PolicySource:     policySource,
		Component:        componentInfo,
		RuleResults:      ruleResults,
	}, nil
}

// SnapshotGenerator handles VSA predicate generation for application snapshots
type SnapshotGenerator struct {
	Report            applicationsnapshot.Report
	timestampProvider func() time.Time
}

// NewSnapshotGenerator creates a new VSA predicate generator for snapshots
func NewSnapshotGenerator(report applicationsnapshot.Report) PredicateGenerator {
	return &SnapshotGenerator{
		Report:            report,
		timestampProvider: time.Now,
	}
}

// NewSnapshotGeneratorWithTime creates a generator with custom time provider (for testing)
func NewSnapshotGeneratorWithTime(report applicationsnapshot.Report, timestampProvider func() time.Time) PredicateGenerator {
	return &SnapshotGenerator{
		Report:            report,
		timestampProvider: timestampProvider,
	}
}

// GeneratePredicate creates a Predicate for the entire application snapshot
// The comp parameter is ignored for snapshot VSAs
func (g *SnapshotGenerator) GeneratePredicate(ctx context.Context, comp applicationsnapshot.Component) (*Predicate, error) {
	log.Infof("Generating snapshot VSA predicate for snapshot: %s", g.Report.Snapshot)

	// Reuse existing predicate generation logic but adapt for snapshot
	validationResult := "failed"
	if g.Report.Success {
		validationResult = "passed"
	}

	policySource := ""
	if g.Report.Policy.Name != "" {
		policySource = g.Report.Policy.Name
	}

	// Aggregate all rule results from all components
	ruleResults := make([]evaluator.Result, 0)
	for _, component := range g.Report.Components {
		ruleResults = append(ruleResults, component.Violations...)
		ruleResults = append(ruleResults, component.Warnings...)
		ruleResults = append(ruleResults, component.Successes...)
	}

	// Create component info for snapshot
	componentInfo := map[string]interface{}{
		"snapshot":       g.Report.Snapshot,
		"componentCount": len(g.Report.Components),
		"components":     g.Report.Components,
	}

	return &Predicate{
		ImageRef:         g.Report.Snapshot, // Use snapshot name as image ref for compatibility
		ValidationResult: validationResult,
		Timestamp:        g.timestampProvider().UTC().Format(time.RFC3339),
		Verifier:         "ec-cli",
		PolicySource:     policySource,
		Component:        componentInfo,
		RuleResults:      ruleResults,
		// Snapshot-specific fields
		SnapshotName:   g.Report.Snapshot,
		ComponentCount: len(g.Report.Components),
		SnapshotDigest: calculateSnapshotDigest(g.Report.Components),
	}, nil
}

// calculateSnapshotDigest creates a unique digest for the entire snapshot
func calculateSnapshotDigest(components []applicationsnapshot.Component) string {
	if len(components) == 0 {
		return ""
	}

	var digests []string
	for _, comp := range components {
		if comp.ContainerImage != "" {
			digests = append(digests, comp.ContainerImage)
		}
	}

	if len(digests) == 0 {
		return ""
	}

	// Sort for consistency
	sort.Strings(digests)

	// Create hash of all digests
	hash := sha256.Sum256([]byte(strings.Join(digests, "|")))
	return fmt.Sprintf("sha256:%x", hash)
}

// Writer handles VSA file writing
type Writer struct {
	FS            afero.Fs    // defaults to the package-level FS or afero.NewOsFs()
	TempDirPrefix string      // defaults to "vsa-"
	FilePerm      os.FileMode // defaults to 0600
}

// NewWriter creates a new VSA file writer
func NewWriter() *Writer {
	return &Writer{
		FS:            afero.NewOsFs(),
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}
}

// WritePredicate writes the Predicate as a JSON file to a temp directory and returns the path.
func (w *Writer) WritePredicate(predicate *Predicate) (string, error) {
	log.Infof("Writing VSA for image: %s", predicate.ImageRef)

	// Serialize with indent
	data, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal VSA predicate: %w", err)
	}

	// Create temp directory using the injected FS and prefix
	tempDir, err := afero.TempDir(w.FS, "", w.TempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	fullPath := filepath.Join(tempDir, "vsa.json")

	log.Infof("Writing VSA file to %s", fullPath)
	// Write file with injected FS and file-permissions
	if err := afero.WriteFile(w.FS, fullPath, data, w.FilePerm); err != nil {
		log.Errorf("Failed to write VSA file to %s: %v", fullPath, err)
		return "", fmt.Errorf("failed to write VSA file: %w", err)
	}

	return fullPath, nil
}

// IsSnapshotVSA returns true if this predicate represents a snapshot VSA
func (p *Predicate) IsSnapshotVSA() bool {
	return p.SnapshotName != ""
}

// GetIdentifier returns the appropriate identifier for this predicate
func (p *Predicate) GetIdentifier() string {
	if p.IsSnapshotVSA() {
		return p.SnapshotName
	}
	return p.ImageRef
}

// AttestationUploader is a function that uploads an attestation and returns a result string or error
// This allows pluggable upload logic (OCI, Rekor, None, or custom)
type AttestationUploader func(ctx context.Context, att oci.Signature, location string) (string, error)

// Built-in uploaders
func OCIUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to OCI registry for %s", location)
	// TODO: Implement OCI upload logic here
	return "", fmt.Errorf("OCI upload not implemented")
}

func RekorUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to Rekor for %s", location)
	// TODO: Implement Rekor upload logic here
	return "", fmt.Errorf("rekor upload not implemented")
}

func NoopUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Upload type is 'none'; skipping upload for %s", location)
	return "", nil
}

// SnapshotAttestor implements PredicateAttestor for application snapshots
type SnapshotAttestor struct {
	PredicatePath  string
	PredicateType  string
	SnapshotName   string
	SnapshotDigest string
	Signer         *Signer
}

// NewSnapshotAttestor creates a new attestor for snapshot VSAs
func NewSnapshotAttestor(
	predicatePath string,
	snapshotName string,
	snapshotDigest string,
	signer *Signer,
) PredicateAttestor {
	return &SnapshotAttestor{
		PredicatePath:  predicatePath,
		PredicateType:  "https://conforma.dev/verification_summary/v1",
		SnapshotName:   snapshotName,
		SnapshotDigest: snapshotDigest,
		Signer:         signer,
	}
}

// AttestPredicate implements PredicateAttestor.AttestPredicate
func (a *SnapshotAttestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	tempAttestor := &Attestor{
		PredicatePath: a.PredicatePath,
		PredicateType: a.PredicateType,
		ImageDigest:   a.SnapshotDigest,
		Repo:          a.SnapshotName,
		Signer:        a.Signer,
	}
	return tempAttestor.AttestPredicate(ctx)
}

// WriteEnvelope implements PredicateAttestor.WriteEnvelope
func (a *SnapshotAttestor) WriteEnvelope(data []byte) (string, error) {
	tempAttestor := &Attestor{
		PredicatePath: a.PredicatePath,
		PredicateType: a.PredicateType,
		ImageDigest:   a.SnapshotDigest,
		Repo:          a.SnapshotName,
		Signer:        a.Signer,
	}
	return tempAttestor.WriteEnvelope(data)
}

// GenerateAndWriteSnapshotVSA generates and writes a snapshot VSA predicate using the orchestrator.
func GenerateAndWriteSnapshotVSA(
	ctx context.Context,
	report applicationsnapshot.Report,
	writer PredicateWriter,
) (string, error) {
	generator := NewSnapshotGenerator(report)
	// The component is ignored for snapshot generator, so we can pass an empty one.
	return GenerateAndWriteVSA(ctx, generator, writer, applicationsnapshot.Component{})
}

// AttestSnapshotVSA signs and envelops a snapshot VSA using the orchestrator.
func AttestSnapshotVSA(
	ctx context.Context,
	predicatePath string,
	report applicationsnapshot.Report,
	signer *Signer,
) (string, error) {
	attestor := NewSnapshotAttestor(
		predicatePath,
		report.Snapshot,
		calculateSnapshotDigest(report.Components),
		signer,
	)
	// The component is ignored for snapshot attestor, so we can pass an empty one.
	return AttestVSA(ctx, attestor, applicationsnapshot.Component{})
}

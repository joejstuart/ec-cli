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

package evaluator

import (
	"encoding/json"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/opa/rule"
)

//////////////////////////////////////////////////////////////////////////////
// test scaffolding
//////////////////////////////////////////////////////////////////////////////

func makeSource(ruleData string, includes []string) ecc.Source {
	s := ecc.Source{}
	if ruleData != "" {
		s.RuleData = &extv1.JSON{Raw: json.RawMessage(ruleData)}
	}
	if len(includes) > 0 {
		s.Config = &ecc.SourceConfig{Include: includes}
	}
	return s
}

// MockRuleSelector implements RuleSelector for testing
type MockRuleSelector struct {
	packagesToEvaluate []string
	shouldReport       map[string]bool
	explainExclusion   map[string]string
	includedRules      map[string][]string
	allRules           map[string]rule.Info
}

func NewMockRuleSelector() *MockRuleSelector {
	return &MockRuleSelector{
		shouldReport:     make(map[string]bool),
		explainExclusion: make(map[string]string),
		includedRules:    make(map[string][]string),
		allRules:         make(map[string]rule.Info),
	}
}

func (m *MockRuleSelector) PackagesToEvaluate(allRules map[string]rule.Info) []string {
	return m.packagesToEvaluate
}

func (m *MockRuleSelector) ShouldReport(ruleID string, imageDigest string, effectiveTime time.Time) bool {
	return m.shouldReport[ruleID]
}

func (m *MockRuleSelector) ExplainExclusion(ruleID string) string {
	return m.explainExclusion[ruleID]
}

func (m *MockRuleSelector) GetIncludedRules(packageName string) []string {
	return m.includedRules[packageName]
}

func (m *MockRuleSelector) SetAllRules(allRules map[string]rule.Info) {
	m.allRules = allRules
}

//////////////////////////////////////////////////////////////////////////////
// UnifiedFilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestUnifiedFilterFactory(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{"pkg1", "pkg2"}

	factory := NewUnifiedFilterFactory(mockSelector)
	source := makeSource(`{"pipeline_intention":"release"}`, []string{"@security"})

	filters := factory.CreateFilters(source)

	assert.Len(t, filters, 1, "Should create exactly one filter")

	// Test that the filter is a UnifiedRuleFilter
	unifiedFilter, ok := filters[0].(*UnifiedRuleFilter)
	assert.True(t, ok, "Filter should be a UnifiedRuleFilter")
	assert.Equal(t, mockSelector, unifiedFilter.selector, "Filter should use the provided selector")
}

//////////////////////////////////////////////////////////////////////////////
// UnifiedRuleFilter tests
//////////////////////////////////////////////////////////////////////////////

func TestUnifiedRuleFilter(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{"pkg1", "pkg3"}

	filter := NewUnifiedRuleFilter(mockSelector)

	rules := []rule.Info{
		{Code: "pkg1.rule1", Package: "pkg1", ShortName: "rule1"},
		{Code: "pkg2.rule1", Package: "pkg2", ShortName: "rule1"},
		{Code: "pkg3.rule1", Package: "pkg3", ShortName: "rule1"},
	}

	// Test that only packages returned by the selector are included
	assert.True(t, filter.Include("pkg1", rules), "pkg1 should be included")
	assert.False(t, filter.Include("pkg2", rules), "pkg2 should be excluded")
	assert.True(t, filter.Include("pkg3", rules), "pkg3 should be included")
}

func TestUnifiedRuleFilterWithEmptySelector(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{} // Empty list

	filter := NewUnifiedRuleFilter(mockSelector)

	rules := []rule.Info{
		{Code: "pkg1.rule1", Package: "pkg1", ShortName: "rule1"},
		{Code: "pkg2.rule1", Package: "pkg2", ShortName: "rule1"},
	}

	// Test that no packages are included when selector returns empty list
	assert.False(t, filter.Include("pkg1", rules), "pkg1 should be excluded")
	assert.False(t, filter.Include("pkg2", rules), "pkg2 should be excluded")
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter tests
//////////////////////////////////////////////////////////////////////////////

func TestNamespaceFilter(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg1.rule2": {Package: "pkg1", ShortName: "rule2"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
		"pkg3.rule1": {Package: "pkg3", ShortName: "rule1"},
	}

	// Create mock filters
	mockFilter1 := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": true, "pkg3": false}}
	mockFilter2 := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false, "pkg3": false}}

	namespaceFilter := NewNamespaceFilter(mockFilter1, mockFilter2)
	result := namespaceFilter.Filter(rules)

	// Only pkg1 should pass both filters (AND logic)
	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

func TestNamespaceFilterWithNoFilters(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	namespaceFilter := NewNamespaceFilter() // No filters
	result := namespaceFilter.Filter(rules)

	// When no filters are provided, all packages should be included
	assert.ElementsMatch(t, []string{"pkg1", "pkg2"}, result)
}

func TestNamespaceFilterWithSingleFilter(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	mockFilter := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false}}
	namespaceFilter := NewNamespaceFilter(mockFilter)
	result := namespaceFilter.Filter(rules)

	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

// MockRuleFilter implements RuleFilter for testing
type MockRuleFilter struct {
	includeMap map[string]bool
}

func (m *MockRuleFilter) Include(pkg string, rules []rule.Info) bool {
	return m.includeMap[pkg]
}

//////////////////////////////////////////////////////////////////////////////
// Helper function tests
//////////////////////////////////////////////////////////////////////////////

func TestFilterNamespaces(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	mockFilter := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false}}
	result := filterNamespaces(rules, mockFilter)

	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

func TestExtractStringArrayFromRuleData(t *testing.T) {
	tests := []struct {
		name     string
		ruleData string
		key      string
		expected []string
	}{
		{
			name:     "single string value",
			ruleData: `{"pipeline_intention":"release"}`,
			key:      "pipeline_intention",
			expected: []string{"release"},
		},
		{
			name:     "array of strings",
			ruleData: `{"pipeline_intention":["release","production"]}`,
			key:      "pipeline_intention",
			expected: []string{"release", "production"},
		},
		{
			name:     "non-existent key",
			ruleData: `{"other_key":"value"}`,
			key:      "pipeline_intention",
			expected: nil,
		},
		{
			name:     "empty ruleData",
			ruleData: "",
			key:      "pipeline_intention",
			expected: nil,
		},
		{
			name:     "invalid JSON",
			ruleData: `{"invalid":json}`,
			key:      "pipeline_intention",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := ecc.Source{}
			if tc.ruleData != "" {
				source.RuleData = &extv1.JSON{Raw: json.RawMessage(tc.ruleData)}
			}

			result := extractStringArrayFromRuleData(source, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"context"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// ExampleFilterFactory demonstrates how to use multiple factories with different behaviors
type ExampleFilterFactory struct{}

func NewExampleFilterFactory() FilterFactory {
	return &ExampleFilterFactory{}
}

// CreateFilters creates multiple filters with different behaviors
func (f *ExampleFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	var filters []RuleFilter

	// 1. Pipeline intention filtering - only evaluate packages with matching pipeline_intention
	pipelineFactory := NewPipelineIntentionFilterFactory()
	pipelineFilters := pipelineFactory.CreateFilters(source)
	filters = append(filters, pipelineFilters...)

	// 2. Custom filtering logic can be added here
	// For example, you could add:
	// - Security level filtering
	// - Environment-specific filtering
	// - Time-based filtering
	// - Custom metadata filtering

	return filters
}

// MultiFactoryExample demonstrates how to use multiple factories together
func MultiFactoryExample(ctx context.Context, source ecc.Source, rules policyRules) []string {
	// Example 1: Use only pipeline intention filtering
	pipelineFactory := NewPipelineIntentionFilterFactory()
	pipelineFilters := pipelineFactory.CreateFilters(source)
	pipelineNamespaces := filterNamespaces(rules, pipelineFilters...)
	log.Debugf("Pipeline intention filtering result: %v", pipelineNamespaces)

	// Example 2: Use only unified filtering
	// (This would require a RuleSelector instance)
	// unifiedFactory := NewUnifiedFilterFactory(ruleSelector)
	// unifiedFilters := unifiedFactory.CreateFilters(source)
	// unifiedNamespaces := filterNamespaces(rules, unifiedFilters...)

	// Example 3: Combine multiple factories (AND logic)
	exampleFactory := NewExampleFilterFactory()
	exampleFilters := exampleFactory.CreateFilters(source)
	combinedNamespaces := filterNamespaces(rules, exampleFilters...)
	log.Debugf("Combined filtering result: %v", combinedNamespaces)

	return combinedNamespaces
}

// UsageExamples demonstrates different ways to use the filtering system
func UsageExamples() {
	// Example 1: Pipeline intention filtering only
	// This will only evaluate packages that contain rules with pipeline_intention metadata
	// matching the configured values in ruleData
	source1 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{"pipeline_intention": ["release", "production"]}`)},
	}

	// Example 2: No pipeline intention filtering
	// This will only evaluate packages that contain rules WITHOUT pipeline_intention metadata
	source2 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{}`)}, // No pipeline_intention configured
	}

	// Example 3: Pipeline intention with include list
	// This combines pipeline intention filtering with explicit include criteria
	source3 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{"pipeline_intention": ["release"]}`)},
		Config: &ecc.SourceConfig{
			Include: []string{"@security", "release"},
		},
	}

	// The filtering system will:
	// 1. Only evaluate packages with rules that have pipeline_intention: ["release"]
	// 2. Only include results from rules that have pipeline_intention: ["release"]
	// 3. Apply additional include/exclude criteria if configured

	log.Debugf("Source 1: %+v", source1)
	log.Debugf("Source 2: %+v", source2)
	log.Debugf("Source 3: %+v", source3)
}

// CustomFilterFactory demonstrates how to create a custom filter factory
type CustomFilterFactory struct {
	// Add custom configuration fields as needed
	securityLevel string
	environment   string
}

func NewCustomFilterFactory(securityLevel, environment string) FilterFactory {
	return &CustomFilterFactory{
		securityLevel: securityLevel,
		environment:   environment,
	}
}

// CreateFilters creates custom filters based on the factory configuration
func (f *CustomFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	var filters []RuleFilter

	// Add custom filtering logic here
	// For example:
	// - Filter by security level
	// - Filter by environment
	// - Filter by custom metadata
	// - Combine with existing filters

	// Example: Add pipeline intention filtering
	pipelineFactory := NewPipelineIntentionFilterFactory()
	pipelineFilters := pipelineFactory.CreateFilters(source)
	filters = append(filters, pipelineFilters...)

	// Example: Add custom security level filtering
	if f.securityLevel != "" {
		// Custom filter implementation would go here
		// securityFilter := NewSecurityLevelFilter(f.securityLevel)
		// filters = append(filters, securityFilter)
	}

	return filters
}

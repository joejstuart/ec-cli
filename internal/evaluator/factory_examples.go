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

	"github.com/conforma/cli/internal/policy/source"
)

// FactorySwappingExamples demonstrates how to easily swap factories with different behaviors
func FactorySwappingExamples() {
	// Example 1: Use Unified Filter Factory (default behavior)
	log.Info("=== Example 1: Unified Filter Factory ===")
	// This provides comprehensive filtering including pipeline intentions, includes/excludes, volatile exclusions
	// unifiedFactory := NewUnifiedFilterFactory(ruleSelector)
	// evaluator, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, unifiedFactory)

	// Example 2: Use Pipeline Intention Filter Factory (dedicated pipeline filtering)
	log.Info("=== Example 2: Pipeline Intention Filter Factory ===")
	// This provides focused pipeline intention filtering only
	pipelineFactory := NewPipelineIntentionFilterFactory()
	log.Infof("Pipeline factory created: %T", pipelineFactory)

	// Example 3: Use Custom Filter Factory (combines multiple behaviors)
	log.Info("=== Example 3: Custom Filter Factory ===")
	customFactory := NewCustomFilterFactory("high", "production")
	log.Infof("Custom factory created: %T", customFactory)

	// Example 4: Use Example Filter Factory (demonstrates composition)
	log.Info("=== Example 4: Example Filter Factory ===")
	exampleFactory := NewExampleFilterFactory()
	log.Infof("Example factory created: %T", exampleFactory)
}

// DemonstrateFactorySwapping shows how to swap factories in practice
func DemonstrateFactorySwapping(ctx context.Context, policySources []source.PolicySource, config ConfigProvider, source ecc.Source) {
	log.Info("=== Factory Swapping Demonstration ===")

	// Scenario 1: Use unified filtering (default)
	log.Info("Scenario 1: Unified filtering")
	// evaluator1, err := NewConftestEvaluator(ctx, policySources, config, source)
	// if err != nil {
	//     log.Errorf("Failed to create unified evaluator: %v", err)
	//     return
	// }
	// result1, err := evaluator1.Evaluate(ctx, target)
	// log.Infof("Unified filtering result: %d outcomes", len(result1))

	// Scenario 2: Use pipeline intention filtering only
	log.Info("Scenario 2: Pipeline intention filtering only")
	// imageContext := &ImageContext{Time: config.EffectiveTime()}
	// ruleSelector := NewUnifiedRuleSelector(source, config, imageContext)
	// pipelineFactory := NewPipelineIntentionFilterFactory()
	// evaluator2, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, pipelineFactory)
	// if err != nil {
	//     log.Errorf("Failed to create pipeline evaluator: %v", err)
	//     return
	// }
	// result2, err := evaluator2.Evaluate(ctx, target)
	// log.Infof("Pipeline filtering result: %d outcomes", len(result2))

	// Scenario 3: Use custom filtering
	log.Info("Scenario 3: Custom filtering")
	// customFactory := NewCustomFilterFactory("high", "production")
	// evaluator3, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, customFactory)
	// if err != nil {
	//     log.Errorf("Failed to create custom evaluator: %v", err)
	//     return
	// }
	// result3, err := evaluator3.Evaluate(ctx, target)
	// log.Infof("Custom filtering result: %d outcomes", len(result3))
}

// FactoryComparison shows the differences between factory types
func FactoryComparison() {
	log.Info("=== Factory Comparison ===")

	// Unified Filter Factory
	log.Info("Unified Filter Factory:")
	log.Info("  ✅ Comprehensive filtering (pipeline intentions, includes/excludes, volatile exclusions)")
	log.Info("  ✅ Time-based filtering and effective time filtering")
	log.Info("  ✅ Complex but powerful")
	log.Info("  ❌ More complex configuration")

	// Pipeline Intention Filter Factory
	log.Info("Pipeline Intention Filter Factory:")
	log.Info("  ✅ Focused on pipeline intention filtering only")
	log.Info("  ✅ Simple and predictable behavior")
	log.Info("  ✅ Only evaluates packages with pipeline_intention metadata")
	log.Info("  ✅ Only shows results from rules with matching pipeline_intention")
	log.Info("  ❌ Limited to pipeline intention filtering")

	// Custom Filter Factory
	log.Info("Custom Filter Factory:")
	log.Info("  ✅ Combines multiple filtering behaviors")
	log.Info("  ✅ Extensible for custom requirements")
	log.Info("  ✅ Can include pipeline intention filtering")
	log.Info("  ✅ Can add security level, environment, etc.")
	log.Info("  ❌ Requires custom implementation")
}

// ConfigurationExamples shows different source configurations
func ConfigurationExamples() {
	log.Info("=== Configuration Examples ===")

	// Example 1: Pipeline intention filtering
	source1 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{"pipeline_intention": "release"}`)},
	}
	log.Infof("Source 1 (pipeline intention): %+v", source1)

	// Example 2: No pipeline intention (general-purpose rules only)
	source2 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{}`)},
	}
	log.Infof("Source 2 (no pipeline intention): %+v", source2)

	// Example 3: Pipeline intention with include list
	source3 := ecc.Source{
		RuleData: &extv1.JSON{Raw: []byte(`{"pipeline_intention": "release"}`)},
		Config: &ecc.SourceConfig{
			Include: []string{"@security", "release"},
		},
	}
	log.Infof("Source 3 (pipeline intention + includes): %+v", source3)
}

// UsagePatterns shows common usage patterns
func UsagePatterns() {
	log.Info("=== Usage Patterns ===")

	// Pattern 1: Use default unified filtering
	log.Info("Pattern 1: Default unified filtering")
	log.Info("  evaluator, err := NewConftestEvaluator(ctx, policySources, config, source)")

	// Pattern 2: Use pipeline intention filtering only
	log.Info("Pattern 2: Pipeline intention filtering only")
	log.Info("  pipelineFactory := NewPipelineIntentionFilterFactory()")
	log.Info("  evaluator, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, pipelineFactory)")

	// Pattern 3: Use custom filtering
	log.Info("Pattern 3: Custom filtering")
	log.Info("  customFactory := NewCustomFilterFactory(\"high\", \"production\")")
	log.Info("  evaluator, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, customFactory)")

	// Pattern 4: Compose multiple factories
	log.Info("Pattern 4: Compose multiple factories")
	log.Info("  exampleFactory := NewExampleFilterFactory()")
	log.Info("  evaluator, err := NewConftestEvaluatorWithFilterFactory(ctx, policySources, config, source, exampleFactory)")
}

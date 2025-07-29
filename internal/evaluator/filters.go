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
// SPDX‑License‑Identifier: Apache‑2.0

package evaluator

import (
	"encoding/json"
	"strings"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

//////////////////////////////////////////////////////////////////////////////
// Interfaces
//////////////////////////////////////////////////////////////////////////////

// RuleFilter decides whether an entire package (namespace) should be
// included in the evaluation set.
//
// The filtering system works at the package level - if any rule in a package
// matches the filter criteria, the entire package is included for evaluation.
// This ensures that related rules within the same package are evaluated together.
type RuleFilter interface {
	Include(pkg string, rules []rule.Info) bool
}

// FilterFactory builds a slice of filters for a given `ecc.Source`.
//
// Multiple filters can be applied simultaneously using AND logic - all filters
// must approve a package for it to be included in the evaluation set.
type FilterFactory interface {
	CreateFilters(source ecc.Source) []RuleFilter
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter – applies all filters (logical AND)
//////////////////////////////////////////////////////////////////////////////

// NamespaceFilter applies multiple filters using AND logic.
//
// This filter combines multiple RuleFilter instances and only includes packages
// that pass ALL filters. This allows for complex filtering scenarios where
// multiple criteria must be satisfied.
type NamespaceFilter struct{ filters []RuleFilter }

func NewNamespaceFilter(filters ...RuleFilter) *NamespaceFilter {
	return &NamespaceFilter{filters: filters}
}

// Filter applies all filters to the given rules and returns the list of packages
// that pass all filter criteria.
//
// The filtering process:
// 1. Groups rules by package (namespace)
// 2. For each package, applies all filters in sequence
// 3. Only includes packages that pass ALL filters (AND logic)
// 4. Returns the list of approved package names
//
// This ensures that only the appropriate rules are evaluated based on the
// current configuration and context.
func (nf *NamespaceFilter) Filter(rules policyRules) []string {
	// Group rules by package for efficient filtering
	grouped := make(map[string][]rule.Info)
	for fqName, r := range rules {
		pkg := strings.SplitN(fqName, ".", 2)[0]
		if pkg == "" {
			pkg = fqName // fallback
		}
		grouped[pkg] = append(grouped[pkg], r)
	}

	var out []string
	for pkg, pkgRules := range grouped {
		include := true
		// Apply all filters - package must pass ALL filters to be included
		for _, flt := range nf.filters {
			ok := flt.Include(pkg, pkgRules)

			if !ok {
				include = false
				break // No need to check other filters if this one fails
			}
		}

		if include {
			out = append(out, pkg)
		}
	}
	return out
}

//////////////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////////////

// filterNamespaces is a convenience function that creates a NamespaceFilter
// and applies it to the given rules.
func filterNamespaces(r policyRules, filters ...RuleFilter) []string {
	return NewNamespaceFilter(filters...).Filter(r)
}

// extractStringArrayFromRuleData returns a string slice for `key`.
//
// This function parses the ruleData JSON and extracts string values for the
// specified key. It handles both single string values and arrays of strings.
//
// Examples:
// - ruleData: {"pipeline_intention": "release"} → ["release"]
// - ruleData: {"pipeline_intention": ["release", "production"]} → ["release", "production"]
// - ruleData: {} → []
func extractStringArrayFromRuleData(src ecc.Source, key string) []string {
	if src.RuleData == nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(src.RuleData.Raw, &m); err != nil {
		log.Debugf("ruleData parse error: %v", err)
		return nil
	}
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, i := range v {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

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

package validate

import (
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
)

// createInvalidImageTest creates a test case for invalid image references
func createInvalidImageTest(name, imageRef string) struct {
	name        string
	component   app.SnapshotComponent
	data        *validateVSAData
	expectError bool
	errorMsg    string
} {
	return struct {
		name        string
		component   app.SnapshotComponent
		data        *validateVSAData
		expectError bool
		errorMsg    string
	}{
		name: name,
		component: app.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: imageRef,
		},
		data: &validateVSAData{
			vsaExpiration:               24 * time.Hour,
			ignoreSignatureVerification: true,
			policySpec: ecapi.EnterpriseContractPolicySpec{
				Sources: []ecapi.Source{
					{Name: "test", Policy: []string{"test-policy"}},
				},
			},
		},
		expectError: true,
		errorMsg:    "failed to extract digest",
	}
}

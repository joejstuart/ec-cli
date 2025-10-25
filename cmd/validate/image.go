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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/trace"
	"sort"
	"strings"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/google/go-containerregistry/pkg/name"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/image"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
)

type imageValidationFunc func(context.Context, app.SnapshotComponent, *app.SnapshotSpec, policy.Policy, []evaluator.Evaluator, bool) (*output.Output, error)

var newOPAEvaluator = evaluator.NewOPAEvaluator

// validateImageData holds all the data for the validate image command
type validateImageData struct {
	certificateIdentity         string
	certificateIdentityRegExp   string
	certificateOIDCIssuer       string
	certificateOIDCIssuerRegExp string
	effectiveTime               string
	extraRuleData               []string
	filePath                    string // Deprecated: images replaced this
	filterType                  string
	imageRef                    string
	info                        bool
	input                       string // Deprecated: images replaced this
	ignoreRekor                 bool
	output                      []string
	outputFile                  string
	policy                      policy.Policy
	policyConfiguration         string
	policySource                string
	publicKey                   string
	rekorURL                    string
	snapshot                    string
	spec                        *app.SnapshotSpec
	// Only used to pass the expansion info to the report. Not a cli flag.
	expansion     *applicationsnapshot.ExpansionInfo
	strict        bool
	images        string
	noColor       bool
	forceColor    bool
	workers       int
	vsaEnabled    bool
	vsaSigningKey string
	vsaUpload     []string
	vsaExpiration time.Duration
}

func validateImageCmd(validate imageValidationFunc) *cobra.Command {
	data := &validateImageData{
		strict:        true,
		workers:       5,
		filterType:    "include-exclude", // Default to include-exclude filter
		vsaExpiration: 168 * time.Hour,   // 7 days default
	}

	validOutputFormats := applicationsnapshot.OutputFormats

	cmd := &cobra.Command{
		Use:   "image",
		Short: "Validate conformance of container images with the provided policies",

		Long: hd.Doc(`
			Validate conformance of container images with the provided policies

			For each image, validation is performed in stages to determine if the image
			conforms to the provided policies.

			The first validation stage determines if an image has been signed, and the
			signature matches the provided public key. This is akin to the "cosign verify"
			command.

			The second validation stage determines if one or more attestations exist, and
			those attestations have been signed matching the provided public key, similarly
			to the "cosign verify-attestation" command. This stage temporarily stores the
			attestations for usage in the next stage.

			The final stage verifies the attestations conform to rego policies defined in
			the EnterpriseContractPolicy.

			Validation advances each stage as much as possible for each image in order to
			capture all issues in a single execution.
		`),

		Example: hd.Doc(`
			Validate single image with the policy defined in the EnterpriseContractPolicy
			custom resource named "default" in the enterprise-contract-service Kubernetes
			namespace:

			  ec validate image --image registry/name:tag

			Validate multiple images from an ApplicationSnapshot Spec file:

			  ec validate image --images my-app.yaml

			Validate attestation of images from an inline ApplicationSnapshot Spec:

			  ec validate image --images '{"components":[{"containerImage":"<image url>"}]}'

			Use a different public key than the one from the EnterpriseContractPolicy resource:

			  ec validate image --image registry/name:tag --public-key <path/to/public/key>

			Use a different Rekor URL than the one from the EnterpriseContractPolicy resource:

			  ec validate image --image registry/name:tag --rekor-url https://rekor.example.org

			Return a non-zero status code on validation failure:

			  ec validate image --image registry/name:tag

		  	Return a zero status code even if there are validation failures:

			  ec validate image --image registry/name:tag --strict=false

			Use an EnterpriseContractPolicy resource from the currently active kubernetes context:

			  ec validate image --image registry/name:tag --policy my-policy

			Use an EnterpriseContractPolicy resource from a different namespace:

			  ec validate image --image registry/name:tag --policy my-namespace/my-policy

			Use an inline EnterpriseContractPolicy spec

			  ec validate image --image registry/name:tag --policy '{"publicKey": "<path/to/public/key>"}'

			Use an EnterpriseContractPolicy spec from a local YAML file
			  ec validate image --image registry/name:tag --policy my-policy.yaml

			Use a git url for the policy configuration. In the first example there should be a '.ec/policy.yaml'
			or a 'policy.yaml' inside a directory called 'default' in the top level of the git repo. In the second
			example there should be a '.ec/policy.yaml' or a 'policy.yaml' file in the top level
			of the git repo. For git repos not hosted on 'github.com' or 'gitlab.com', prefix the url with
			'git::'. For the policy configuration files you can use json instead of yaml if you prefer.

			  ec validate image --image registry/name:tag --policy github.com/user/repo//default?ref=main

			  ec validate image --image registry/name:tag --policy github.com/user/repo

			Write output in JSON format to a file

			  ec validate image --image registry/name:tag --output json=<path>

			Write output in YAML format to stdout and in appstudio format to a file

			  ec validate image --image registry/name:tag --output yaml --output appstudio=<path>


			Validate a single image with keyless workflow.

			  ec validate image --image registry/name:tag --policy my-policy \
			    --certificate-identity 'https://github.com/user/repo/.github/workflows/push.yaml@refs/heads/main' \
			    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
			    --rekor-url 'https://rekor.sigstore.dev'

			Use a regular expression to match certificate attributes.

			  ec validate image --image registry/name:tag --policy my-policy \
			    --certificate-identity-regexp '^https://github\.com' \
			    --certificate-oidc-issuer-regexp 'githubusercontent' \
			    --rekor-url 'https://rekor.sigstore.dev'
		`),

		PreRunE: func(cmd *cobra.Command, args []string) error {
			return prepareValidateImageData(cmd, data)
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			return executeValidateImageCommand(cmd, data, validate)
		},
	}

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
		Policy configuration as:
		  * Kubernetes reference ([<namespace>/]<name>)
		  * file (policy.yaml)
		  * git reference (github.com/user/repo//default?ref=main), or
		  * inline JSON ('{sources: {...}, identity: {...}}')")`))

	cmd.Flags().StringVarP(&data.imageRef, "image", "i", data.imageRef, "OCI image reference")

	cmd.Flags().StringVarP(&data.publicKey, "public-key", "k", data.publicKey,
		"path to the public key. Overrides publicKey from EnterpriseContractPolicy")

	cmd.Flags().StringVarP(&data.rekorURL, "rekor-url", "r", data.rekorURL,
		"Rekor URL. Overrides rekorURL from EnterpriseContractPolicy")

	cmd.Flags().BoolVar(&data.ignoreRekor, "ignore-rekor", data.ignoreRekor,
		"Skip Rekor transparency log checks during validation.")

	cmd.Flags().StringVar(&data.certificateIdentity, "certificate-identity", data.certificateIdentity,
		"URL of the certificate identity for keyless verification")

	cmd.Flags().StringVar(&data.certificateIdentityRegExp, "certificate-identity-regexp", data.certificateIdentityRegExp,
		"Regular expression for the URL of the certificate identity for keyless verification")

	cmd.Flags().StringVar(&data.certificateOIDCIssuer, "certificate-oidc-issuer", data.certificateOIDCIssuer,
		"URL of the certificate OIDC issuer for keyless verification")

	cmd.Flags().StringVar(&data.certificateOIDCIssuerRegExp, "certificate-oidc-issuer-regexp", data.certificateOIDCIssuerRegExp,
		"Regular expresssion for the URL of the certificate OIDC issuer for keyless verification")

	// Deprecated: images replaced this
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", data.filePath,
		"DEPRECATED - use --images: path to ApplicationSnapshot Spec JSON file")

	// Deprecated: images replaced this
	cmd.Flags().StringVarP(&data.input, "json-input", "j", data.input,
		"DEPRECATED - use --images: JSON representation of an ApplicationSnapshot Spec")

	cmd.Flags().StringVar(&data.images, "images", data.images,
		"path to ApplicationSnapshot Spec JSON file or JSON representation of an ApplicationSnapshot Spec")

	cmd.Flags().StringSliceVar(&data.output, "output", data.output, hd.Doc(`
		write output to a file in a specific format. Use empty string path for stdout.
		May be used multiple times. Possible formats are:
		`+strings.Join(validOutputFormats, ", ")+`. In following format and file path
		additional options can be provided in key=value form following the question
		mark (?) sign, for example: --output text=output.txt?show-successes=false
	`))

	cmd.Flags().StringVarP(&data.outputFile, "output-file", "o", data.outputFile,
		"[DEPRECATED] write output to a file. Use empty string for stdout, default behavior")

	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict,
		"Return non-zero status on non-successful validation. Defaults to true. Use --strict=false to return a zero status code.")

	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, hd.Doc(`
		Run policy checks with the provided time. Useful for testing rules with
		effective dates in the future. The value can be "now" (default) - for
		current time, "attestation" - for time from the youngest attestation, or
		a RFC3339 formatted value, e.g. 2022-11-18T00:00:00Z.
	`))

	cmd.Flags().StringSliceVar(&data.extraRuleData, "extra-rule-data", data.extraRuleData, hd.Doc(`
		Extra data to be provided to the Rego policy evaluator. Use format 'key=value'. May be used multiple times.
	`))

	cmd.Flags().StringVar(&data.snapshot, "snapshot", "", hd.Doc(`
		Provide the AppStudio Snapshot as a source of the images to validate, as inline
		JSON of the "spec" or a reference to a Kubernetes object [<namespace>/]<name>`))

	cmd.Flags().BoolVar(&data.info, "info", data.info, hd.Doc(`
		Include additional information on the failures. For instance for policy
		violations, include the title and the description of the failed policy
		rule.`))

	cmd.Flags().BoolVar(&data.noColor, "no-color", data.info, hd.Doc(`
		Disable color when using text output even when the current terminal supports it`))

	cmd.Flags().BoolVar(&data.forceColor, "color", data.info, hd.Doc(`
		Enable color when using text output even when the current terminal does not support it`))

	cmd.Flags().IntVar(&data.workers, "workers", data.workers, hd.Doc(`
		Number of workers to use for validation. Defaults to 5.`))

	cmd.Flags().StringVar(&data.filterType, "filter-type", data.filterType, hd.Doc(`
		Filter type to use for policy evaluation. Options: "include-exclude" (default) or "ec-policy".
		- "include-exclude": Uses traditional include/exclude filtering without pipeline intentions
		- "ec-policy": Uses Enterprise Contract policy filtering with pipeline intention support`))

	cmd.Flags().BoolVar(&data.vsaEnabled, "vsa", false, "Generate a Verification Summary Attestation (VSA) for each validated image.")
	cmd.Flags().StringVar(&data.vsaSigningKey, "vsa-signing-key", "", "Path to the private key for signing the VSA. Supports file paths and Kubernetes secret references (k8s://namespace/secret-name/key-field).")
	cmd.Flags().StringSliceVar(&data.vsaUpload, "vsa-upload", nil, "Storage backends for VSA upload. Format: backend@url?param=value. Examples: rekor@https://rekor.sigstore.dev, local@./vsa-dir")
	cmd.Flags().DurationVar(&data.vsaExpiration, "vsa-expiration", data.vsaExpiration, "Expiration threshold for existing VSAs. If a valid VSA exists and is newer than this threshold, validation will be skipped. (default 168h)")

	if len(data.input) > 0 || len(data.filePath) > 0 || len(data.images) > 0 {
		if err := cmd.MarkFlagRequired("image"); err != nil {
			panic(err)
		}
	}

	return cmd
}

// result represents the result of processing a component
type result struct {
	err         error
	component   applicationsnapshot.Component
	policyInput []byte
}

// executeValidateImageCommand executes the main validation logic
func executeValidateImageCommand(cmd *cobra.Command, data *validateImageData, validate imageValidationFunc) error {
	if trace.IsEnabled() {
		ctx, task := trace.NewTask(cmd.Context(), "ec:validate-images")
		cmd.SetContext(ctx)
		defer task.End()
	}

	appComponents := data.spec.Components
	evaluators, err := setupEvaluators(cmd, data)
	if err != nil {
		return err
	}
	defer func() {
		for _, evaluator := range evaluators {
			evaluator.Destroy()
		}
	}()

	showSuccesses, _ := cmd.Flags().GetBool("show-successes")
	showWarnings, _ := cmd.Flags().GetBool("show-warnings")

	components, manyPolicyInput, err := processComponents(cmd, appComponents, data, evaluators, validate, showSuccesses)
	if err != nil {
		return err
	}

	// Ensure some consistency in output.
	sort.Slice(components, func(i, j int) bool {
		return components[i].ContainerImage > components[j].ContainerImage
	})

	if len(data.outputFile) > 0 {
		data.output = append(data.output, fmt.Sprintf("%s=%s", applicationsnapshot.JSON, data.outputFile))
	}

	report, err := generateReport(cmd, data, components, manyPolicyInput, showSuccesses, showWarnings)
	if err != nil {
		return err
	}

	if data.vsaEnabled {
		if err := processVSA(cmd, data, &report); err != nil {
			return err
		}
	}

	if data.strict && !report.Success {
		return errors.New("success criteria not met")
	}

	return nil
}

// processValidationResult processes the validation result and populates the component
func processValidationResult(res *result, out *output.Output, comp app.SnapshotComponent, data *validateImageData, showSuccesses bool) {
	if out != nil {
		// Normal validation completed
		res.component.Violations = out.Violations()
		res.component.Warnings = out.Warnings()

		successes := out.Successes()
		res.component.SuccessCount = len(successes)
		if showSuccesses {
			res.component.Successes = successes
		}

		res.component.Signatures = out.Signatures
		// Create a new result object for attestations. The point is to only keep the data that's needed.
		// For example, the Statement is only needed when the full attestation is printed.
		for _, att := range out.Attestations {
			attResult := applicationsnapshot.NewAttestationResult(att)
			if containsOutput(data.output, "attestation") {
				attResult.Statement = att.Statement()
			}
			res.component.Attestations = append(res.component.Attestations, attResult)
		}
		res.component.ContainerImage = out.ImageURL
		res.policyInput = out.PolicyInput
	} else {
		// Validation was skipped due to valid VSA - no violations, no processing needed
		log.Debugf("Validation skipped for %s due to valid VSA", comp.ContainerImage)
		res.component.ContainerImage = comp.ContainerImage
	}
}

// processExtraRuleData processes extra rule data for policy sources
func processExtraRuleData(p policy.Policy, data *validateImageData) error {
	if len(data.extraRuleData) == 0 {
		return nil
	}

	policySpec := p.Spec()
	sources := policySpec.Sources
	for i := range sources {
		src := sources[i]
		var rule_data_raw []byte
		unmarshaled := make(map[string]interface{})

		if src.RuleData != nil {
			rule_data_raw, err := src.RuleData.MarshalJSON()
			if err != nil {
				return fmt.Errorf("unable to parse ruledata to raw data")
			}
			err = json.Unmarshal(rule_data_raw, &unmarshaled)
			if err != nil {
				return fmt.Errorf("unable to parse ruledata to map")
			}
		}

		for _, extraRuleData := range data.extraRuleData {
			parts := strings.SplitN(extraRuleData, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid extra rule data format: %s", extraRuleData)
			}
			key := parts[0]
			value := parts[1]
			unmarshaled[key] = value
		}

		rule_data_raw, err := json.Marshal(unmarshaled)
		if err != nil {
			return fmt.Errorf("unable to marshal ruledata")
		}
		sources[i].RuleData = &extv1.JSON{Raw: rule_data_raw}
	}
	p = p.WithSpec(policySpec)
	return nil
}

// setupPolicy configures and processes the policy
func setupPolicy(ctx context.Context, data *validateImageData) error {
	policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
	if err != nil {
		return err
	}
	data.policyConfiguration = policyConfiguration

	policyOptions := policy.Options{
		EffectiveTime: data.effectiveTime,
		Identity: cosign.Identity{
			Issuer:        data.certificateOIDCIssuer,
			IssuerRegExp:  data.certificateOIDCIssuerRegExp,
			Subject:       data.certificateIdentity,
			SubjectRegExp: data.certificateIdentityRegExp,
		},
		IgnoreRekor: data.ignoreRekor,
		PolicyRef:   data.policyConfiguration,
		PublicKey:   data.publicKey,
		RekorURL:    data.rekorURL,
	}

	// We're not currently using the policyCache returned from PreProcessPolicy, but we could
	// use it to cache the policy for future use.
	p, _, err := policy.PreProcessPolicy(ctx, policyOptions)
	if err != nil {
		return err
	}

	if err := processExtraRuleData(p, data); err != nil {
		return err
	}
	data.policy = p

	return nil
}

// determineInputSpec determines the input specification for validation
func determineInputSpec(ctx context.Context, data *validateImageData) error {
	s, exp, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
		File:     data.filePath,
		JSON:     data.input,
		Image:    data.imageRef,
		Snapshot: data.snapshot,
		Images:   data.images,
	})
	if err != nil {
		return err
	}
	data.spec = s
	data.expansion = exp
	return nil
}

// generateReport creates and writes the validation report
func generateReport(cmd *cobra.Command, data *validateImageData, components []applicationsnapshot.Component, manyPolicyInput [][]byte, showSuccesses, showWarnings bool) (applicationsnapshot.Report, error) {
	report, err := applicationsnapshot.NewReport(data.snapshot, components, data.policy, manyPolicyInput, showSuccesses, showWarnings, data.expansion)
	if err != nil {
		return applicationsnapshot.Report{}, err
	}
	p := format.NewTargetParser(applicationsnapshot.JSON, format.Options{ShowSuccesses: showSuccesses, ShowWarnings: showWarnings}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
	utils.SetColorEnabled(data.noColor, data.forceColor)
	if err := report.WriteAll(data.output, p); err != nil {
		return applicationsnapshot.Report{}, err
	}
	return report, nil
}

// processComponents processes all components using workers and returns the results
func processComponents(cmd *cobra.Command, appComponents []app.SnapshotComponent, data *validateImageData, evaluators []evaluator.Evaluator, validate imageValidationFunc, showSuccesses bool) ([]applicationsnapshot.Component, [][]byte, error) {
	// worker is responsible for processing one component at a time from the jobs channel,
	// and for emitting a corresponding result for the component on the results channel.
	worker := func(id int, jobs <-chan app.SnapshotComponent, results chan<- result) {
		log.Debugf("Starting worker %d", id)
		for comp := range jobs {
			ctx := cmd.Context()
			var task *trace.Task
			if trace.IsEnabled() {
				ctx, task = trace.NewTask(ctx, "ec:validate-component")
				trace.Logf(ctx, "", "workerID=%d", id)
			}

			log.Debugf("Worker %d got a component %q", id, comp.ContainerImage)

			res := processComponent(ctx, comp, data, evaluators, validate, showSuccesses)

			if task != nil {
				task.End()
			}
			results <- res
		}
		log.Debugf("Done with worker %d", id)
	}

	numComponents := len(appComponents)

	// Set numWorkers to the value from our flag. The default is 5.
	numWorkers := data.workers

	jobs := make(chan app.SnapshotComponent, numComponents)
	results := make(chan result, numComponents)
	// Initialize each worker. They will wait patiently until a job is sent to the jobs
	// channel, or the jobs channel is closed.
	for i := 0; i <= numWorkers; i++ {
		go worker(i, jobs, results)
	}
	// Initialize all the jobs. Each worker will pick a job from the channel when the worker
	// is ready to consume a new job.
	for _, c := range appComponents {
		jobs <- c
	}
	close(jobs)

	var components []applicationsnapshot.Component
	var manyPolicyInput [][]byte
	var allErrors error = nil
	for i := 0; i < numComponents; i++ {
		r := <-results
		if r.err != nil {
			e := fmt.Errorf("error validating image %s of component %s: %w", r.component.ContainerImage, r.component.Name, r.err)
			allErrors = errors.Join(allErrors, e)
		} else {
			components = append(components, r.component)
			manyPolicyInput = append(manyPolicyInput, r.policyInput)
		}
	}
	close(results)
	if allErrors != nil {
		return nil, nil, allErrors
	}

	return components, manyPolicyInput, nil
}

// setupEvaluators creates evaluators for the policy sources
func setupEvaluators(cmd *cobra.Command, data *validateImageData) ([]evaluator.Evaluator, error) {
	evaluators := []evaluator.Evaluator{}

	// Return an evaluator for each of these
	for _, sourceGroup := range data.policy.Spec().Sources {
		// Todo: Make each fetch run concurrently
		log.Debugf("Fetching policy source group '%s'", sourceGroup.Name)
		policySources := source.PolicySourcesFrom(sourceGroup)

		for _, policySource := range policySources {
			log.Debugf("policySource: %#v", policySource)
		}

		var c evaluator.Evaluator
		var err error
		if utils.IsOpaEnabled() {
			c, err = newOPAEvaluator()
		} else {
			// Use the unified filtering approach with the specified filter type
			c, err = evaluator.NewConftestEvaluatorWithFilterType(
				cmd.Context(), policySources, data.policy, sourceGroup, data.filterType)
		}

		if err != nil {
			log.Debug("Failed to initialize the conftest evaluator!")
			return nil, err
		}

		evaluators = append(evaluators, c)
	}

	return evaluators, nil
}

// processComponent processes a single component and returns the result
func processComponent(ctx context.Context, comp app.SnapshotComponent, data *validateImageData, evaluators []evaluator.Evaluator, validate imageValidationFunc, showSuccesses bool) result {
	// Use VSA-aware validation if VSA checking is enabled and a retriever is available
	var out *output.Output
	var err error
	if data.vsaExpiration > 0 {
		vsaChecker := vsa.CreateVSACheckerFromUploadFlags(data.vsaUpload)
		if vsaChecker != nil {
			out, err = image.ValidateImageWithVSACheck(ctx, comp, data.spec, data.policy, evaluators, data.info, vsaChecker, data.vsaExpiration)
		} else {
			// Fall back to normal validation if no VSA retriever is available
			out, err = validate(ctx, comp, data.spec, data.policy, evaluators, data.info)
		}
	} else {
		// Use original validation when VSA checking is disabled
		out, err = validate(ctx, comp, data.spec, data.policy, evaluators, data.info)
	}
	res := result{
		err: err,
		component: applicationsnapshot.Component{
			SnapshotComponent: comp,
			Success:           err == nil,
		},
	}

	// Skip on err to not panic. Error is return on routine completion.
	if err == nil {
		processValidationResult(&res, out, comp, data, showSuccesses)
	}
	res.component.Success = err == nil && len(res.component.Violations) == 0

	return res
}

// processVSA handles VSA processing and upload
func processVSA(cmd *cobra.Command, data *validateImageData, report *applicationsnapshot.Report) error {
	// Use the signer function that supports both file and k8s:// URLs
	signer, err := vsa.NewSigner(cmd.Context(), data.vsaSigningKey, utils.FS(cmd.Context()))
	if err != nil {
		log.Error(err)
		return err
	}

	// Create VSA service
	vsaService := vsa.NewServiceWithFS(signer, utils.FS(cmd.Context()), data.policySource, data.policy)

	// Define helper functions for getting git URL and digest
	getGitURL := func(comp applicationsnapshot.Component) string {
		if comp.Source.GitSource != nil {
			return comp.Source.GitSource.URL
		}
		return ""
	}

	getDigest := func(comp applicationsnapshot.Component) (string, error) {
		imageRef, err := name.ParseReference(comp.ContainerImage)
		if err != nil {
			return "", fmt.Errorf("failed to parse image reference %s: %v", comp.ContainerImage, err)
		}

		digest, err := oci.NewClient(cmd.Context()).ResolveDigest(imageRef)
		if err != nil {
			return "", fmt.Errorf("failed to resolve digest for image %s: %v", comp.ContainerImage, err)
		}

		return digest, nil
	}

	// Process all VSAs using the service
	vsaResult, err := vsaService.ProcessAllVSAs(cmd.Context(), *report, getGitURL, getDigest)
	if err != nil {
		log.Errorf("Failed to process VSAs: %v", err)
		// Don't return error here, continue with the rest of the command
		return nil
	}

	// Upload VSAs to configured storage backends
	if len(data.vsaUpload) > 0 {
		return uploadVSAs(cmd, data, vsaResult, signer)
	}

	// No upload backends configured - inform user about next steps
	totalFiles := len(vsaResult.ComponentEnvelopes)
	if vsaResult.SnapshotEnvelope != "" {
		totalFiles++
	}

	if totalFiles > 0 {
		log.Errorf("[VSA] VSA files generated but not uploaded (no --vsa-upload backends specified)")
	}

	return nil
}

// uploadVSAs uploads VSA envelopes to configured storage backends
func uploadVSAs(cmd *cobra.Command, data *validateImageData, vsaResult *vsa.VSAProcessingResult, signer *vsa.Signer) error {
	log.Infof("[VSA] Starting upload to %d storage backend(s)", len(data.vsaUpload))

	// Upload component VSA envelopes
	for imageRef, envelopePath := range vsaResult.ComponentEnvelopes {
		uploadErr := vsa.UploadVSAEnvelope(cmd.Context(), envelopePath, data.vsaUpload, signer)
		if uploadErr != nil {
			log.Errorf("[VSA] Upload failed for component %s: %v", imageRef, uploadErr)
		} else {
			log.Infof("[VSA] Uploaded Component VSA")
		}
	}

	// Upload snapshot VSA envelope if it exists
	if vsaResult.SnapshotEnvelope != "" {
		uploadErr := vsa.UploadVSAEnvelope(cmd.Context(), vsaResult.SnapshotEnvelope, data.vsaUpload, signer)
		if uploadErr != nil {
			log.Errorf("[VSA] Upload failed for snapshot: %v", uploadErr)
		} else {
			log.Infof("[VSA] Uploaded Snapshot VSA")
		}
	}

	return nil
}

// prepareValidateImageData prepares the data for the validate image command
func prepareValidateImageData(cmd *cobra.Command, data *validateImageData) error {
	ctx := cmd.Context()
	if trace.IsEnabled() {
		var task *trace.Task
		ctx, task = trace.NewTask(ctx, "ec:validate-image-prepare")
		defer task.End()
		cmd.SetContext(ctx)
	}

	if err := determineInputSpec(ctx, data); err != nil {
		return err
	}

	// Store policy source before resolution
	data.policySource = data.policyConfiguration

	if err := setupPolicy(ctx, data); err != nil {
		return err
	}

	return nil
}

// find if the slice contains "value" output
func containsOutput(data []string, value string) bool {
	for _, item := range data {
		newItem := strings.Split(item, "=")
		if newItem[0] == value {
			return true
		}
	}
	return false
}

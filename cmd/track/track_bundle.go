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

package track

import (
	"context"
	"os"
	"strings"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/utils"
)

type (
	trackBundleFn func(context.Context, []string, []byte, bool, bool, int) ([]byte, error)
	pullImageFn   func(context.Context, string) ([]byte, error)
	pushImageFn   func(context.Context, string, []byte, string) error
)

func trackBundleCmd(track trackBundleFn, pullImage pullImageFn, pushImage pushImageFn) *cobra.Command {
	params := struct {
		bundles      []string
		gits         []string
		input        string
		prune        bool
		replace      bool
		output       string
		freshen      bool
		inEffectDays int
	}{
		prune:        true,
		inEffectDays: 60,
	}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Record tracking information about Tekton bundles",

		Long: hd.Doc(`
			Record tracking information about Tekton bundles

			Each Tekton Bundle is expected to be a proper OCI image reference. They
			may contain a tag, a digest, or both. If a digest is not provided, this
			command will query the registry to determine its value. Either a tag
			or a digest is required.

			The output is meant to assist enforcement of policies that ensure the
			most recent Tekton Bundle is used. Each entry contains an "expires_on"
			date which indicates when that specific bundle version should no longer
			be used. When a new entry is introduced, an expiration date is added to
			the previous newest entry.

			If --prune is set, on by default, expired entries are removed.
			Any entry with an expires_on date in the future (or no expires_on date)
			is considered current and will not be pruned.
		`),

		Example: hd.Doc(`
			Track multiple bundles:

			  ec track bundle --bundle <IMAGE1> --bundle <IMAGE2>

			Save tracking information into a new tracking file:

			  ec track bundle --bundle <IMAGE1> --output <path/to/new/file>

			Save tracking information into an image registry:

			  ec track bundle --bundle <IMAGE1> --output <oci:registry.io/repository/image:tag>

			Extend an existing tracking file with a new bundle:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file>

			Extend an existing tracking file with a new bundle and save changes:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --replace

			Extend an existing tracking image with a new bundle and push to an image registry:

			  ec track bundle --bundle <IMAGE1> --input <oci:registry.io/repository/image:tag> --replace

			Skip pruning for unacceptable entries:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --prune=false

			Update existing acceptable bundles:

			  ec track bundle --input <path/to/input/file> --output <path/to/input/file> --freshen
		`),

		Args:    cobra.NoArgs,
		Aliases: []string{"tekton-task"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeTrackBundle(cmd, params, track, pullImage, pushImage)
		},
	}

	cmd.Flags().StringVarP(&params.input, "input", "i", params.input, "existing tracking file")

	cmd.Flags().StringSliceVarP(&params.bundles, "bundle", "b", params.bundles,
		"bundle image reference to track - may be used multiple times")

	cmd.Flags().StringSliceVarP(&params.gits, "git", "g", params.gits,
		"git references to track - may be used multiple times")

	cmd.Flags().BoolVarP(&params.prune, "prune", "p", params.prune,
		"remove entries that are no longer acceptable, i.e. a newer entry already effective exists")

	cmd.Flags().BoolVarP(&params.replace, "replace", "r", params.replace, "write changes to input file")

	cmd.Flags().StringVarP(&params.output, "output", "o", params.output,
		"write modified tracking file to a file. Use empty string for stdout, default behavior")

	cmd.Flags().BoolVar(&params.freshen, "freshen", params.freshen, "resolve image tags to catch updates and use the latest image for the tag")

	cmd.Flags().IntVar(&params.inEffectDays, "in-effect-days", params.inEffectDays, "number of days after which older bundle entries expire when a new bundle entry is added (most recent entry stays valid until replaced)")

	cmd.MarkFlagsOneRequired("bundle", "git", "input")

	return cmd
}

// executeTrackBundle handles the main logic for the track bundle command
func executeTrackBundle(cmd *cobra.Command, params struct {
	bundles      []string
	gits         []string
	input        string
	prune        bool
	replace      bool
	output       string
	freshen      bool
	inEffectDays int
}, track trackBundleFn, pullImage pullImageFn, pushImage pushImageFn) error {
	// capture the command and arguments so we can keep track of what
	// Tekton bundles were used to getnerate the OPA/Conftest bundle
	invocation := strings.Join(os.Args, " ")
	fs := utils.FS(cmd.Context())

	data, err := loadInputData(fs, params.input, pullImage)
	if err != nil {
		return err
	}

	urls := append(params.bundles, params.gits...)

	out, err := track(cmd.Context(), urls, data, params.prune, params.freshen, params.inEffectDays)
	if err != nil {
		return err
	}

	if err := writeOutput(cmd, fs, params.output, out, invocation, pushImage); err != nil {
		return err
	}

	if params.replace && params.input != "" {
		return handleReplace(fs, params.input, out, invocation, pushImage)
	}

	return nil
}

// loadInputData loads input data from file or OCI registry
func loadInputData(fs afero.Fs, input string, pullImage pullImageFn) ([]byte, error) {
	if strings.HasPrefix(input, "oci:") {
		return pullImage(context.Background(), strings.TrimPrefix(input, "oci:"))
	}
	if input != "" {
		return afero.ReadFile(fs, input)
	}
	return nil, nil
}

// writeOutput writes the output to stdout, file, or OCI registry
func writeOutput(cmd *cobra.Command, fs afero.Fs, output string, out []byte, invocation string, pushImage pushImageFn) error {
	switch {
	case output == "":
		_, err := cmd.OutOrStdout().Write(out)
		return err
	case strings.HasPrefix(output, "oci:"):
		return pushImage(cmd.Context(), strings.TrimPrefix(output, "oci:"), out, invocation)
	default:
		return afero.WriteFile(fs, output, out, 0666)
	}
}

// handleReplace handles the replace logic for input files
func handleReplace(fs afero.Fs, input string, out []byte, invocation string, pushImage pushImageFn) error {
	if strings.HasPrefix(input, "oci:") {
		return pushImage(context.Background(), strings.TrimPrefix(input, "oci:"), out, invocation)
	}

	stat, err := fs.Stat(input)
	if err != nil {
		return err
	}
	perm := stat.Mode()

	return afero.WriteFile(fs, input, out, perm)
}

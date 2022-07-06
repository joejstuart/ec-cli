/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/hacbs-contract/ec-cli/internal/pipeline"
	"github.com/spf13/cobra"
)

func signOffCmd() *cobra.Command {
	// signOffCmd represents the signOff command
	var data = struct {
		imageRef          string
		PolicyRepo        string
		PolicyDir         string
		Ref               string
		ConftestNamespace string
		publicKey         string
	}{
		imageRef:          "",
		PolicyRepo:        "https://github.com/hacbs-contract/ec-policies.git",
		PolicyDir:         "policy",
		ConftestNamespace: "pipeline.main",
		Ref:               "main",
		publicKey:         "",
	}
	cmd := &cobra.Command{
		Use:   "signOff",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
	and usage of using your command. For example:

	Cobra is a CLI library for Go that empowers applications.
	This application is a tool to generate the needed files
	to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			imageValidator, err := image.NewImageValidator(cmd.Context(), data.imageRef, data.publicKey, "")
			if err != nil {
				return err
			}

			validatedImage, err := imageValidator.ValidateImage(cmd.Context())
			if err != nil {
				return err
			}

			fmt.Println("validated image")
			for _, att := range validatedImage.Attestations {
				signoffSource, err := att.BuildSignoffSource()
				if err != nil {
					return err
				}
				signOff, _ := signoffSource.GetBuildSignOff()
				fmt.Printf("%v\n", signOff)
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&data.publicKey, "public-key", "", "Public key")
	cmd.Flags().StringVar(&data.imageRef, "image-ref", data.imageRef, "The OCI repo to fetch the attestation from.")
	cmd.Flags().StringVar(&data.PolicyDir, "policy-dir", data.PolicyDir, "Subdirectory containing policies, if not in default 'policy' subdirectory.")
	cmd.Flags().StringVar(&data.PolicyRepo, "policy-repo", data.PolicyRepo, "Git repo containing policies.")
	cmd.Flags().StringVar(&data.Ref, "branch", data.Ref, "Branch to use.")
	cmd.Flags().StringVar(&data.ConftestNamespace, "namespace", data.ConftestNamespace, "Namespace of policy to validate against")

	// fetch the attestation using the oci-repo and image-digests
	return cmd
}

func validateSignOff(ctx context.Context, policySource pipeline.PolicyRepo, conftestNamespace string) error {

	return errors.New("bad")
}

func init() {
	rootCmd.AddCommand(signOffCmd())

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signOffCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signOffCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

package evaluator

import (
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
)

type Criteria struct {
	include []string
	exclude []string
}

func NewCriteria(source ecc.Source, p ConfigProvider, image string) Criteria {
	include, exclude := computeIncludeExclude(source, p, image)
	return Criteria{
		include: include,
		exclude: exclude,
	}
}

func computeIncludeExclude(src ecc.Source, p ConfigProvider, image string) ([]string, []string) {
	var include, exclude []string

	sc := src.Config

	// The lines below take care to make a copy of the includes/excludes slices in order
	// to ensure mutations are not unexpectedly propagated.
	if sc != nil && (len(sc.Include) != 0 || len(sc.Exclude) != 0) {
		include = append(include, sc.Include...)
		exclude = append(exclude, sc.Exclude...)
	}

	vc := src.VolatileConfig
	if vc != nil {
		at := p.EffectiveTime()
		filter := func(items []string, criteria []ecc.VolatileCriteria) []string {
			for _, c := range criteria {
				from, err := time.Parse(time.RFC3339, c.EffectiveOn)
				if err != nil {
					if c.EffectiveOn != "" {
						log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveOn, err)
					}
					from = at
				}
				until, err := time.Parse(time.RFC3339, c.EffectiveUntil)
				if err != nil {
					if c.EffectiveUntil != "" {
						log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveUntil, err)
					}
					until = at
				}
				if until.Compare(at) >= 0 && from.Compare(at) <= 0 {
					if c.ImageRef != "" && c.ImageRef == image {
						items = append(items, c.Value)
					} else if c.ImageRef == "" {
						items = append(items, c.Value)
					}
				}
			}

			return items
		}

		include = filter(include, vc.Include)
		exclude = filter(exclude, vc.Exclude)
	}

	if policyConfig := p.Spec().Configuration; len(include) == 0 && len(exclude) == 0 && policyConfig != nil {
		include = append(include, policyConfig.Include...)
		exclude = append(exclude, policyConfig.Exclude...)
		// If the old way of specifying collections are used, convert them.
		for _, collection := range policyConfig.Collections {
			include = append(include, fmt.Sprintf("@%s", collection))
		}
	}

	if len(include) == 0 {
		include = []string{"*"}
	}

	return include, exclude
}

// func imageFound(components []app.SnapshotComponent, imageRef string) (bool, error) {
// 	for _, comp := range components {
// 		if digest, err := parseDigest(comp.ContainerImage); err == nil {
// 			if digest == imageRef {
// 				return true, nil
// 			}
// 		} else {
// 			return false, err
// 		}
// 	}
// 	return false, nil
// }

// func parseDigest(image string) (string, error) {
// 	// Parse the image reference
// 	ref, err := reference.ParseNormalizedNamed(image)
// 	if err != nil {
// 		fmt.Println("Error parsing image reference:", err)
// 		return "", err
// 	}

// 	canonicalRef, ok := ref.(reference.Canonical)
// 	if !ok {
// 		return "", errors.New("no digest found in image reference")
// 	}

// 	return canonicalRef.Digest().String(), nil
// }

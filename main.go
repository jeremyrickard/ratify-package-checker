package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blang/semver"
	"github.com/deislabs/ratify/pkg/common"
	"github.com/deislabs/ratify/pkg/ocispecs"
	"github.com/deislabs/ratify/pkg/referrerstore"
	_ "github.com/deislabs/ratify/pkg/referrerstore/oras"
	"github.com/deislabs/ratify/pkg/verifier"
	"github.com/deislabs/ratify/pkg/verifier/plugin/skel"
	jsonLoader "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
)

const (
	SpdxJsonMediaType string = "application/spdx+json"
	SpdxTextMediaType string = "text/spdx"
)

func main() {
	skel.PluginMain("kubecon-demo", "1.0.0", VerifyReference, []string{"1.0.0"})
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for the input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(
	args *skel.CmdArgs,
	subjectReference common.Reference,
	descriptor ocispecs.ReferenceDescriptor,
	store referrerstore.ReferrerStore,
) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, descriptor)
	if err != nil {
		return nil, err
	}

	if len(referenceManifest.Blobs) == 0 {
		return &verifier.VerifierResult{
			Name:      input.Name,
			IsSuccess: false,
			Message:   fmt.Sprintf("KubeCon EU Demo Failed: no blobs found for referrer %s@%s", subjectReference.Path, descriptor.Digest.String()),
		}, nil
	}

	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			return &verifier.VerifierResult{
				Name:      input.Name,
				IsSuccess: false,
				Message:   fmt.Sprintf("Error fetching blob for subject: %s digest: %s", subjectReference, blobDesc.Digest),
			}, err
		}
		doc, err := getSPDXDoc(refBlob)
		if err != nil {
			return &verifier.VerifierResult{
				Name:      input.Name,
				IsSuccess: false,
				Message:   fmt.Sprintf("unknown media type: %s digest: %s", subjectReference, blobDesc.Digest),
			}, err
		}

		badPackageLookup := map[string][]string{}
		for _, pkg := range input.DisallowedPackages {
			pkgs, ok := badPackageLookup[pkg.Name]
			if !ok {
				pkgs = []string{}
				badPackageLookup[pkg.Name] = pkgs
			}
			badPackageLookup[pkg.Name] = append(pkgs, pkg.Version)
		}

		badPackageLicenseLookup := map[string]struct{}{}
		for _, license := range input.DisallowedLicenses {
			badPackageLicenseLookup[license] = struct{}{}
		}

		badPackagesLicenses := []PackageLicense{}
		badPackageVersions := []Package{}
		for _, p := range doc.Packages {
			_, ok := badPackageLicenseLookup[p.PackageLicenseConcluded]
			if ok {
				badPackagesLicenses = append(badPackagesLicenses, PackageLicense{
					PackageName:    p.PackageName,
					PackageLicense: p.PackageLicenseConcluded,
				})
			}
			versions, ok := badPackageLookup[p.PackageName]
			if ok {
				matched, err := contains(versions, p.PackageVersion)
				if err != nil {
					return &verifier.VerifierResult{
						Name:      input.Name,
						IsSuccess: false,
						Message:   fmt.Sprintf("unable to compute verisons for: %s digest: %s", subjectReference, blobDesc.Digest),
					}, err
				}
				if matched {
					badPackageVersions = append(badPackageVersions, Package{
						Name:    p.PackageName,
						Version: p.PackageVersion,
					})
				}
			}
		}
		messages := []string{}
		if len(badPackagesLicenses) > 0 {
			messages = append(messages, fmt.Sprintf("disallowed licenses found: %s", badPackagesLicenses))
		}
		if len(badPackageVersions) > 0 {
			messages = append(messages, fmt.Sprintf("disallowed package versions found %s", badPackageVersions))
		}
		if len(messages) > 0 {
			return &verifier.VerifierResult{
				Name:      input.Name,
				IsSuccess: false,
				Message:   strings.Join(messages, ","),
			}, err
		}
	}
	return &verifier.VerifierResult{
		Name:      input.Name,
		IsSuccess: true,
		Message:   "successful verification",
	}, nil
}

func getSPDXDoc(refBlob []byte) (*spdx.Document, error) {
	doc, err := processSpdxJsonMediaType(refBlob)
	if err != nil {
		return processSpdxTextMediaType(refBlob)
	}
	return doc, err
}

func processSpdxJsonMediaType(refBlob []byte) (*spdx.Document, error) {
	return jsonLoader.Read(bytes.NewReader(refBlob))
}

func processSpdxTextMediaType(refBlob []byte) (*spdx.Document, error) {
	return tagvalue.Read(bytes.NewReader(refBlob))
}

func contains(versions []string, version string) (bool, error) {
	for _, ver := range versions {
		if ver == version {
			return true, nil
		}
		v, err := semver.Parse(ver)
		if err != nil {
			return false, err
		}
		pkgVersion, err := semver.Parse(version)
		if err != nil {
			return false, err
		}
		return v.GTE(pkgVersion), nil
	}
	return false, nil
}

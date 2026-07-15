package main

import (
	"os"
	"strings"
	"testing"
)

const sharedWorkflowSHA = "578137212ead4ab4059e95df17fa30e9b7ac4aed"

func readPublicationFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func TestPublicationUsesReviewedSharedWorkflows(t *testing.T) {
	publisher := readPublicationFile(t, ".github/workflows/lint-test-build-push.yaml")
	for _, required := range []string{
		"libops/.github/.github/workflows/build-push.yaml@" + sharedWorkflowSHA,
		"additional-gar-registry: us-docker.pkg.dev/libops-images/public",
		"expected-main-sha:",
		"scan: true",
		"sign: true",
		"certificate-identity: https://github.com/libops/.github/.github/workflows/build-push.yaml@" + sharedWorkflowSHA,
	} {
		if !strings.Contains(publisher, required) {
			t.Errorf("publisher workflow must contain %q", required)
		}
	}

	release := readPublicationFile(t, ".github/workflows/github-release.yaml")
	if !strings.Contains(release, "libops/.github/.github/workflows/bump-release.yaml@"+sharedWorkflowSHA) {
		t.Fatal("release workflow must use the reviewed shared release workflow")
	}
	for _, forbidden := range []string{"build-push.yaml@main", "bump-release.yaml@main", "secrets: inherit"} {
		if strings.Contains(publisher, forbidden) || strings.Contains(release, forbidden) {
			t.Errorf("publication workflows must not contain %q", forbidden)
		}
	}

	config := readPublicationFile(t, ".goreleaser.yml")
	for _, required := range []string{"version: 2", "version_template:"} {
		if !strings.Contains(config, required) {
			t.Errorf("GoReleaser config must contain %q", required)
		}
	}
}

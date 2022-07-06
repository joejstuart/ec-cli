package image

import (
	"errors"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
)

type invocation struct {
	ConfigSource map[string]interface{} `json:"configSource"`
	Parameters   map[string]interface{} `json:"parameters"`
	Environment  map[string]interface{} `json:"environment"`
}

type predicate struct {
	Invocation  invocation               `json:"invocation"`
	BuildType   string                   `json:"buildType"`
	Metadata    map[string]interface{}   `json:"metadata"`
	Builder     map[string]interface{}   `json:"builder"`
	BuildConfig map[string]interface{}   `json:"buildConfig"`
	Materials   []map[string]interface{} `json:"materials"`
}

type attestation struct {
	Predicate     predicate                `json:"predicate"`
	PredicateType string                   `json:"predicateType"`
	Subject       []map[string]interface{} `json:"subject"`
	Type          string                   `json:"_type"`
}

type buildSigner interface {
	GetBuildSignOff() (string, error)
}

type repoSignoffSource struct {
	source    *git.Repository
	commit    string
	jiraMatch string
}

type jiraSignoffSource struct {
	source string
	jiraid string
}

func (a *attestation) BuildSignoffSource() (buildSigner, error) {
	// the signoff source can be determined by looking into the attestation.
	// the attestation can have an env var or something that this can key off of
	repo, err := a.getRepository()
	if err != nil {
		return nil, err
	}
	if repo != nil {
		commit, err := a.getBuildCommitMessage()
		if err != nil {
			return nil, err
		}

		return &repoSignoffSource{
			source:    repo,
			commit:    commit,
			jiraMatch: "(?i)RedHat JIRA Issue: ([a-zA-Z]+-\\d+)",
		}, nil
	}

	return nil, nil
}

func (a *attestation) getBuildCommitSha() string {
	return "4be9282d0c47ff3046fd56c8067e6f0e83822a77"
}

func (a *attestation) getBuildSCM() string {
	return "https://github.com/joejstuart/ec-policies.git"
}

func (a *attestation) getRepository() (*git.Repository, error) {
	return git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: a.getBuildSCM(),
	})
}

func (a *attestation) getBuildCommitMessage() (string, error) {
	repo, err := a.getRepository()
	if err != nil {
		return "", err
	}

	commit, err := repo.CommitObject(plumbing.NewHash(a.getBuildCommitSha()))
	if err != nil {
		return "", err
	}

	return commit.Message, nil
}

func (b *repoSignoffSource) GetBuildSignOff() (string, error) {
	var jiras []string
	re := regexp.MustCompile(b.jiraMatch)
	match := re.FindStringSubmatch(b.commit)
	if len(match) < 1 {
		return "", errors.New(
			"there were no jira references found.",
		)
	}
	jiras = append(jiras, match[len(match)-1])
	return strings.Join(jiras, ","), nil
}

func (j *jiraSignoffSource) GetBuildSignOff() (string, error) {
	// parse the signatures in the commit
	return j.jiraid, nil
}

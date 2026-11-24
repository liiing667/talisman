package utility

import (
	"crypto/sha256"
	"encoding/hex"
	"talisman/gitrepo"

	"github.com/sirupsen/logrus"
)

type SHA256Hasher interface {
	CollectiveSHA256Hash(paths []string) string
	Start() error
	Shutdown() error
}

type DefaultSHA256Hasher struct{}

// CollectiveSHA256Hash return collective sha256 hash of the passed paths
func (*DefaultSHA256Hasher) CollectiveSHA256Hash(paths []string) string {
	return collectiveSHA256Hash(paths, SafeReadFile)
}

func (*DefaultSHA256Hasher) Start() error    { return nil }
func (*DefaultSHA256Hasher) Shutdown() error { return nil }

type gitBatchSHA256Hasher struct {
	br gitrepo.BatchReader
}

func (g *gitBatchSHA256Hasher) CollectiveSHA256Hash(paths []string) string {
	return collectiveSHA256Hash(paths, g.br.Read)
}

func (g *gitBatchSHA256Hasher) Start() error {
	return g.br.Start()
}

func (g *gitBatchSHA256Hasher) Shutdown() error {
	return g.br.Shutdown()
}

func hashByte(contentPtr *[]byte) string {
	contents := *contentPtr
	hasher := sha256.New()
	hasher.Write(contents)
	return hex.EncodeToString(hasher.Sum(nil))
}

func collectiveSHA256Hash(paths []string, FileReader func(string) ([]byte, error)) string {
	var finHash = ""
	for _, path := range paths {
		fileBytes, _ := FileReader(path)
		finHash = hashPathAndContent(finHash, path, fileBytes)
	}
	c := []byte(finHash)
	m := hashByte(&c)
	return m
}

// CollectiveSHA256HashForContent returns the collective hash for a path whose
// content has already been read. It uses the same algorithm as
// CollectiveSHA256Hash, allowing callers to bind an already-captured file
// snapshot to the checksum they report instead of re-reading the path.
func CollectiveSHA256HashForContent(path string, content []byte) string {
	finHash := hashPathAndContent("", path, content)
	c := []byte(finHash)
	return hashByte(&c)
}

func hashPathAndContent(previousHash string, path string, content []byte) string {
	previousHashBytes := []byte(previousHash)
	concatBytes := hashByte(&previousHashBytes)
	nameByte := []byte(path)
	nameHash := hashByte(&nameByte)
	contentHash := hashByte(&content)
	return concatBytes + contentHash + nameHash
}

var hashers = make(map[string]SHA256Hasher)

// MakeHasher returns a SHA256 file/object hasher based on mode and a repo root
func MakeHasher(mode string, root string) SHA256Hasher {
	if hashers[mode] != nil {
		return hashers[mode]
	}
	switch mode {
	case "pre-push":
		hashers[mode] = &gitBatchSHA256Hasher{gitrepo.NewBatchGitHeadPathReader(root)}
	case "pre-commit":
		hashers[mode] = &gitBatchSHA256Hasher{gitrepo.NewBatchGitStagedPathReader(root)}
	case "scan":
		hashers[mode] = &gitBatchSHA256Hasher{gitrepo.NewBatchGitObjectHashReader(root)}
	case "pattern":
		hashers[mode] = &DefaultSHA256Hasher{}
	case "checksum":
		hashers[mode] = &gitBatchSHA256Hasher{gitrepo.NewBatchGitStagedPathReader(root)}
	case "default":
		hashers[mode] = &DefaultSHA256Hasher{}
	}
	err := hashers[mode].Start()
	if err != nil {
		logrus.Errorf("unable to start hasher: %v", err)
		return nil
	}
	return hashers[mode]
}

func DestroyHashers() {
	for _, hasher := range hashers {
		hasher.Shutdown()
	}
	hashers = make(map[string]SHA256Hasher)
}

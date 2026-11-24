package filename

import (
	"fmt"
	"regexp"
	"strings"
	"talisman/detector/detector"
	"talisman/detector/helpers"
	"talisman/detector/severity"

	"talisman/gitrepo"
	"talisman/talismanrc"

	log "github.com/sirupsen/logrus"
)

var (
	filenamePatterns = []*severity.PatternSeverity{
		{Pattern: regexp.MustCompile(`^.+_rsa$`), Severity: severity.SeverityConfiguration["RSAFile"]},
		{Pattern: regexp.MustCompile(`^.+_dsa.*$`), Severity: severity.SeverityConfiguration["DSAFile"]},
		{Pattern: regexp.MustCompile(`^.+_ed25519$`), Severity: severity.SeverityConfiguration["DSAFile"]},
		{Pattern: regexp.MustCompile(`^.+_ecdsa$`), Severity: severity.SeverityConfiguration["DSAFile"]},
		{Pattern: regexp.MustCompile(`^\.\w+_history$`), Severity: severity.SeverityConfiguration["ShellHistory"]},
		{Pattern: regexp.MustCompile(`^.+\.pem$`), Severity: severity.SeverityConfiguration["PemFile"]},
		{Pattern: regexp.MustCompile(`^.+\.ppk$`), Severity: severity.SeverityConfiguration["PpkFile"]},
		{Pattern: regexp.MustCompile(`^.+\.key(pair)?$`), Severity: severity.SeverityConfiguration["KeyPairFile"]},
		{Pattern: regexp.MustCompile(`^.+\.pkcs12$`), Severity: severity.SeverityConfiguration["PKCSFile"]},
		{Pattern: regexp.MustCompile(`^.+\.pfx$`), Severity: severity.SeverityConfiguration["PFXFile"]},
		{Pattern: regexp.MustCompile(`^.+\.p12$`), Severity: severity.SeverityConfiguration["P12File"]},
		{Pattern: regexp.MustCompile(`^.+\.asc$`), Severity: severity.SeverityConfiguration["ASCFile"]},
		{Pattern: regexp.MustCompile(`^\.?htpasswd$`), Severity: severity.SeverityConfiguration["HTPASSWDFile"]},
		{Pattern: regexp.MustCompile(`^\.?netrc$`), Severity: severity.SeverityConfiguration["NetrcFile"]},
		{Pattern: regexp.MustCompile(`^.*\.tblk$`), Severity: severity.SeverityConfiguration["TunnelBlockFile"]},
		{Pattern: regexp.MustCompile(`^.*\.ovpn$`), Severity: severity.SeverityConfiguration["OpenVPNFile"]},
		{Pattern: regexp.MustCompile(`^.*\.kdb$`), Severity: severity.SeverityConfiguration["KDBFile"]},
		{Pattern: regexp.MustCompile(`^.*\.agilekeychain$`), Severity: severity.SeverityConfiguration["AgileKeyChainFile"]},
		{Pattern: regexp.MustCompile(`^.*\.keychain$`), Severity: severity.SeverityConfiguration["KeyChainFile"]},
		{Pattern: regexp.MustCompile(`^.*\.key(store|ring)$`), Severity: severity.SeverityConfiguration["KeyStoreFile"]},
		{Pattern: regexp.MustCompile(`^jenkins\.plugins\.publish_over_ssh\.BapSshPublisherPlugin.xml$`), Severity: severity.SeverityConfiguration["JenkinsPublishOverSSHFile"]},
		{Pattern: regexp.MustCompile(`^credentials\.xml$`), Severity: severity.SeverityConfiguration["CredentialsXML"]},
		{Pattern: regexp.MustCompile(`^.*\.pubxml(\.user)?$`), Severity: severity.SeverityConfiguration["PubXML"]},
		{Pattern: regexp.MustCompile(`^\.?s3cfg$`), Severity: severity.SeverityConfiguration["s3Config"]},
		{Pattern: regexp.MustCompile(`^\.gitrobrc$`), Severity: severity.SeverityConfiguration["GitRobRC"]},
		{Pattern: regexp.MustCompile(`^\.?(bash|zsh)rc$`), Severity: severity.SeverityConfiguration["ShellRC"]},
		{Pattern: regexp.MustCompile(`^\.?(bash_|zsh_)?profile$`), Severity: severity.SeverityConfiguration["ShellProfile"]},
		{Pattern: regexp.MustCompile(`^\.?(bash_|zsh_)?aliases$`), Severity: severity.SeverityConfiguration["ShellAlias"]},
		{Pattern: regexp.MustCompile(`^secret_token.rb$`), Severity: severity.SeverityConfiguration["SecretToken"]},
		{Pattern: regexp.MustCompile(`^omniauth.rb$`), Severity: severity.SeverityConfiguration["OmniAuth"]},
		{Pattern: regexp.MustCompile(`^carrierwave.rb$`), Severity: severity.SeverityConfiguration["CarrierWaveRB"]},
		{Pattern: regexp.MustCompile(`^schema.rb$`), Severity: severity.SeverityConfiguration["SchemaRB"]},
		{Pattern: regexp.MustCompile(`^database.yml$`), Severity: severity.SeverityConfiguration["DatabaseYml"]},
		{Pattern: regexp.MustCompile(`^settings.py$`), Severity: severity.SeverityConfiguration["PythonSettings"]},
		{Pattern: regexp.MustCompile(`^.*(config)(\.inc)?\.php$`), Severity: severity.SeverityConfiguration["PhpConfig"]},
		{Pattern: regexp.MustCompile(`^LocalSettings.php$`), Severity: severity.SeverityConfiguration["PhpLocalSettings"]},
		{Pattern: regexp.MustCompile(`\.?env`), Severity: severity.SeverityConfiguration["EnvFile"]},
		{Pattern: regexp.MustCompile(`\bdump|dump\b`), Severity: severity.SeverityConfiguration["BDumpFile"]},
		{Pattern: regexp.MustCompile(`\bsql|sql\b`), Severity: severity.SeverityConfiguration["BSQLFile"]},
		{Pattern: regexp.MustCompile(`\bdump|dump\b`), Severity: severity.SeverityConfiguration["BDumpFile"]},
		{Pattern: regexp.MustCompile(`password`), Severity: severity.SeverityConfiguration["PasswordFile"]},
		{Pattern: regexp.MustCompile(`backup`), Severity: severity.SeverityConfiguration["BackupFile"]},
		{Pattern: regexp.MustCompile(`private.*key`), Severity: severity.SeverityConfiguration["PrivateKeyFile"]},
		{Pattern: regexp.MustCompile(`(oauth).*(token)`), Severity: severity.SeverityConfiguration["OauthTokenFile"]},
		{Pattern: regexp.MustCompile(`^.*\.log$`), Severity: severity.SeverityConfiguration["LogFile"]},
		{Pattern: regexp.MustCompile(`^\.?kwallet$`), Severity: severity.SeverityConfiguration["KWallet"]},
		{Pattern: regexp.MustCompile(`^\.?gnucash$`), Severity: severity.SeverityConfiguration["GNUCash"]},
	}
)

// FileNameDetector represents tests performed against the fileName of the Additions.
// The Paths of the supplied Additions are tested against the configured patterns and if any of them match, it is logged as a failure during the run
type FileNameDetector struct {
	flagPatterns []*severity.PatternSeverity
	threshold    severity.Severity
}

// DefaultFileNameDetector returns a FileNameDetector that tests Additions against the pre-configured patterns
func DefaultFileNameDetector(threshold severity.Severity) detector.Detector {
	return NewFileNameDetector(filenamePatterns, threshold)
}

// NewFileNameDetector returns a FileNameDetector that tests Additions against the supplied patterns
func NewFileNameDetector(patternsWithSeverity []*severity.PatternSeverity, threshold severity.Severity) detector.Detector {
	return FileNameDetector{patternsWithSeverity, threshold}
}

// Test tests the fileNames of the Additions to ensure that they don't look suspicious
func (fd FileNameDetector) Test(comparator helpers.IgnoreEvaluator, currentAdditions []gitrepo.Addition, ignoreConfig *talismanrc.TalismanRC, result *helpers.DetectionResults, additionCompletionCallback func()) {
	for _, addition := range currentAdditions {
		if comparator.ShouldIgnore(addition, "filename") {
			log.WithFields(log.Fields{
				"filePath": addition.Path,
			}).Info("Ignoring addition as it was specified to be ignored.")
			result.Ignore(addition.Path, "filename")
			additionCompletionCallback()
			continue
		}
		for _, patternWithSeverity := range fd.flagPatterns {
			if matchesAnyPlatformView(patternWithSeverity.Pattern, string(addition.Name)) {
				log.WithFields(log.Fields{
					"filePath": addition.Path,
					"pattern":  patternWithSeverity.Pattern,
					"severity": patternWithSeverity.Severity,
				}).Info("Failing file as it matched pattern.")
				if patternWithSeverity.Severity.ExceedsThreshold(fd.threshold) {
					result.Fail(addition.Path, "filename", fmt.Sprintf("The file name %q failed checks against the pattern %s", addition.Path, patternWithSeverity.Pattern), addition.Commits, patternWithSeverity.Severity)
				} else {
					result.Warn(addition.Path, "filename", fmt.Sprintf("The file name %q failed checks against the pattern %s", addition.Path, patternWithSeverity.Pattern), addition.Commits, patternWithSeverity.Severity)
				}
			}
		}
		additionCompletionCallback()
	}
}

// matchesAnyPlatformView reports whether the pattern matches the file name
// either verbatim or under the identity that case-insensitive,
// trailing-dot/space-stripping platforms (Windows, and macOS by default)
// would fold it to.
//
// A commit created on such a platform may record names like "CREDENTIALS.XML"
// or "secrets.pem." which are the very same on-disk file as their folded
// identity ("credentials.xml", "secrets.pem"). Checking both views gives those
// names the same detection identity no matter which view a scanning mode
// (pre-push, pre-commit, pattern, scan) happens to observe, while the
// verbatim check keeps genuinely case-sensitive names (e.g. LocalSettings.php
// on Linux) matched - and only matched - by their exact-case patterns.
func matchesAnyPlatformView(pattern *regexp.Regexp, name string) bool {
	for _, view := range platformViews(name) {
		if pattern.MatchString(view) {
			return true
		}
	}
	return false
}

// platformViews returns the distinct names under which platforms may present
// the same file: the name verbatim, the name with trailing dots and spaces
// stripped (Windows does not preserve them), and that name case-folded
// (Windows and, by default, macOS are case-insensitive). Views that collapse
// to the verbatim name or to the empty string are omitted.
func platformViews(name string) []string {
	trimmedName := strings.TrimRight(name, ". ")
	foldedName := strings.ToLower(trimmedName)
	views := []string{name}
	if trimmedName != "" && trimmedName != name {
		views = append(views, trimmedName)
	}
	if foldedName != "" && foldedName != name && foldedName != trimmedName {
		views = append(views, foldedName)
	}
	return views
}

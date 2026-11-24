package severity

import "fmt"

var SeverityConfiguration = map[string]Severity{
	"ConsumerKeyPattern":        High,
	"ConsumerSecretParrern":     High,
	"AWSKeyPattern":             High,
	"AWSSecretPattern":          High,
	"RSAKeyPattern":             High,
	"DSAFile":                   High,
	"PrivateKeyFile":            High,
	"PemFile":                   High,
	"PpkFile":                   High,
	"SecretToken":               High,
	"KeyPairFile":               High,
	"CustomPattern":             High,
	"PKCSFile":                  High,
	"PFXFile":                   High,
	"P12File":                   High,
	"NetrcFile":                 High,
	"RSAFile":                   High,
	"KeyChainFile":              High,
	"KeyStoreFile":              High,
	"OauthTokenFile":            High,
	"HTPASSWDFile":              High,
	"TunnelBlockFile":           High,
	"CredentialsXML":            High,
	"JenkinsPublishOverSSHFile": High,
	"Base64Content":             High,
	"HexContent":                High,
	"s3Config":                  Medium,
	"OpenVPNFile":               Medium,
	"DatabaseYml":               Medium,
	"ShellHistory":              Low,
	"ASCFile":                   Low,
	"KDBFile":                   Low,
	"AgileKeyChainFile":         Low,
	"PubXML":                    Low,
	"GitRobRC":                  Low,
	"ShellRC":                   Low,
	"CreditCardContent":         Low,
	"ShellProfile":              Low,
	"ShellAlias":                Low,
	"OmniAuth":                  Low,
	"CarrierWaveRB":             Low,
	"SchemaRB":                  Low,
	"PythonSettings":            Low,
	"PhpConfig":                 Low,
	"PhpLocalSettings":          Low,
	"EnvFile":                   Low,
	"BDumpFile":                 Low,
	"BSQLFile":                  Low,
	"PasswordFile":              Low,
	"BackupFile":                Low,
	"LogFile":                   Low,
	"KWallet":                   Low,
	"GNUCash":                   Low,
	"PasswordPhrasePattern":     Low,
	"LargeFileSize":             Low,
}

// DefaultSeverityConfiguration returns a copy of the built-in severity
// configuration. Per-run overrides should be applied on top of this copy (or
// restored from it) so that the defaults themselves are never mutated.
func DefaultSeverityConfiguration() map[string]Severity {
	defaultConfiguration := make(map[string]Severity, len(SeverityConfiguration))
	for detector, severity := range SeverityConfiguration {
		defaultConfiguration[detector] = severity
	}
	return defaultConfiguration
}

// ValidateCustomSeverity ensures that a custom severity override refers to a
// known detector and uses one of the supported severity levels (low, medium,
// high). Anything else must fail closed before a scan starts.
func ValidateCustomSeverity(detector string, customSeverity Severity) error {
	if _, known := SeverityConfiguration[detector]; !known {
		return fmt.Errorf("unknown detector %q in custom severity configuration", detector)
	}
	if customSeverity < Low || customSeverity > High {
		return fmt.Errorf("invalid severity %q for detector %q in custom severity configuration: must be one of low, medium or high", String(customSeverity), detector)
	}
	return nil
}

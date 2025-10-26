module <uuid>

go 1.21

require (
	github.com/preludeorg/libraries/go/tests/dropper v0.0.0
	github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../preludeorg-libraries/go/tests/dropper

replace github.com/preludeorg/libraries/go/tests/endpoint => ../../preludeorg-libraries/go/tests/endpoint

// NOTE: No cert_installer module needed when using LimaCharlie IaC
// Certificate is pre-installed via D&R rule on sensor enrollment

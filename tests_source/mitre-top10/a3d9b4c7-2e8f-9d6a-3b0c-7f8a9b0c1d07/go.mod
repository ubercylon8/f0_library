module a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07

go 1.24.0

toolchain go1.24.11

require (
	github.com/google/uuid v1.6.0
	github.com/preludeorg/libraries/go/tests/dropper v0.0.0
	github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
	golang.org/x/sys v0.37.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../../preludeorg-libraries/go/tests/dropper

replace github.com/preludeorg/libraries/go/tests/endpoint => ../../../preludeorg-libraries/go/tests/endpoint

module f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01

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

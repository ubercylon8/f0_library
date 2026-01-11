module b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02

go 1.21

require (
	github.com/google/uuid v1.6.0
	github.com/preludeorg/libraries/go/tests/dropper v0.0.0
	github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
	golang.org/x/sys v0.15.0
)

replace github.com/preludeorg/libraries/go/tests/dropper => ../../../preludeorg-libraries/go/tests/dropper

replace github.com/preludeorg/libraries/go/tests/endpoint => ../../../preludeorg-libraries/go/tests/endpoint

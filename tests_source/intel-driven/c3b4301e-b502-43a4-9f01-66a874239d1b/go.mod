module c3b4301e-b502-43a4-9f01-66a874239d1b

go 1.21

require (
	github.com/google/uuid v1.6.0
	github.com/preludeorg/libraries/go/tests/cert_installer v0.0.0
	github.com/preludeorg/libraries/go/tests/endpoint v0.0.0
	golang.org/x/sys v0.28.0
)

require golang.org/x/crypto v0.31.0

replace github.com/preludeorg/libraries/go/tests/cert_installer => ../../../preludeorg-libraries/go/tests/cert_installer

replace github.com/preludeorg/libraries/go/tests/endpoint => ../../../preludeorg-libraries/go/tests/endpoint

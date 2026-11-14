# Test certificate chains

Certificate chains for checking whether a trust store still accepts the
compromised eMudhra intermediates, for use with the test hosts at
https://emudhra.we-have-a-problem.com/. Each file holds a full chain in PEM
format, leaf first.

* `regular/` holds the chain served by each of the fourteen test hosts. Two of
  them, marked `noct`, carry a leaf that was never logged to Certificate
  Transparency, so only clients that do not enforce CT accept them.
* `rollover/` holds two chains that are not served by any host. In each, the
  compromised DV G3B intermediate has self-issued a key rollover certificate
  for a new CA key, and that key signs the leaf. They test that a block also
  catches chains built through a rollover certificate, not only leaves signed
  directly by the compromised keys.

Each directory has a `README.txt` describing its chains in detail.

## Offline check

To see whether a trust store still accepts a chain, verify the leaf against
that store using the rest of the file as untrusted intermediates. For the
OpenSSL default store:

    openssl verify -show_chain -untrusted FILE.pem FILE.pem

For a specific bundle:

    openssl verify -show_chain -CAfile /path/to/bundle.pem -untrusted FILE.pem FILE.pem

"OK" means the store still trusts the compromised intermediate. An error naming
the issuer certificate means trust has been removed. Note that `openssl verify`
does not check revocation unless asked to.

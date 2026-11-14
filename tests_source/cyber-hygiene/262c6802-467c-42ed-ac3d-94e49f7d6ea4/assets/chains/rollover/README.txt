Rollover certificate chains for the eMudhra tests
=================================================

Each file holds a full chain in PEM format, leaf first. The leaf
certificates were issued on 27 October 2026.

Why these chains exist
----------------------

RFC 5280 section 6.1.4 (l)
(https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4) says the path
length is not decremented for self-issued certificates, and some clients,
such as OpenSSL, implement this. An impacted intermediate could
self-issue a "key rollover" CA certificate that certifies a new CA key,
and that key could then sign end-entity certificates that pass RFC 5280
path validation. Blocking mechanisms that only match the leaf's Authority
Key Identifier, or only check that the leaf was signed by the key of one
of the impacted intermediate certificates, would not catch these chains.
The rollover certificate has the same subject as the intermediate but is
a different certificate, and it certifies a new CA key. These chains are
here to test for that.

In both chains the leaf was never logged to Certificate Transparency and
carries no SCTs. The leaf is signed by the new CA key certified by the
rollover certificate, which has the subject EM DV TLS CA - G3B. The
rollover certificate is signed by the key of the existing G3B
intermediate, which is cross-signed as below.

Each leaf certifies the same key as the corresponding noct leaf in the
regular directory (dv-g3b-noct-emudhra.we-have-a-problem.com.pem and
dv-g3b-aaa-noct-emudhra.we-have-a-problem.com.pem), so only the signing
CA key and the chain differ.

  dv-g3b-noct-rollover-emudhra.we-have-a-problem.com.pem
      leaf, rollover G3B intermediate, existing G3B intermediate,
      emSign Root TLS CA - G3 (cross-signed by emSign ECC Root CA - G3)

  dv-g3b-aaa-noct-rollover-emudhra.we-have-a-problem.com.pem
      leaf, rollover G3B intermediate, existing G3B intermediate
      cross-signed by AAA Certificate Services

Offline check
-------------

To see whether a trust store still accepts a chain, verify the leaf
against that store using the rest of the file as untrusted intermediates.
For the OpenSSL default store:

  openssl verify -show_chain -untrusted FILE.pem FILE.pem

For a specific bundle:

  openssl verify -show_chain -CAfile /path/to/bundle.pem -untrusted FILE.pem FILE.pem

"OK" means the store still trusts the compromised intermediate.
An error naming the issuer certificate means trust has been removed.
Note that openssl verify does not check revocation unless asked to.

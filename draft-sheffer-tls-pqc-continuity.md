---
title: "PQC Continuity: Downgrade Protection for TLS Servers Migrating to PQC"
abbrev: "PQC Continuity"
category: std

docname: draft-sheffer-tls-pqc-continuity-latest
submissiontype: IETF
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - PQC
 - TLS
 - Downgrade Attacks
venue:
  github: "yaronf/draft-sheffer-tls-pqc-continuity"
  latest: "https://yaronf.github.io/draft-sheffer-tls-pqc-continuity/draft-sheffer-tls-pqc-continuity.html"

author:
 -
    fullname: Yaron Sheffer
    organization: Intuit
    email: yaronf.ietf@gmail.com
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "k.tirumaleswar_reddy@nokia.com"

normative:

informative:


--- abstract

As the Internet transitions toward post-quantum cryptography (PQC), many TLS servers will continue supporting
traditional certificates to maintain compatibility with legacy clients. However, this coexistence introduces a significant vulnerability: an undetected rollback attack, where a malicious actor strips the PQC or Composite certificate and forces the use of a traditional certificate once quantum-capable adversaries exist. 

To defend against this, this document defines a TLS extension that allows a client to cache a server's declared commitment to present PQC or composite certificates for a specified duration. On subsequent connections, clients enforce that cached commitment and reject traditional-only certificates that conflict with it. This mechanism, inspired by HTTP Strict Transport Security (HSTS) but operating at the TLS layer provides PQC downgrade protection without requiring changes to certificate authority (CA) infrastructure.

--- middle

# Introduction

The migration to post-quantum cryptography (PQC) will be gradual. Servers will
likely host both traditional and PQC (or composite) certificates to maintain
compatibility: legacy clients can still connect, while updated ones benefit
from PQC authentication. The size of the legacy client base often drives the
decision to keep traditional certificates. Relevant PQC work includes
{{?I-D.ietf-lamps-dilithium-certificates}} (ML-DSA),
{{?I-D.ietf-lamps-x509-slhdsa}} (SLH-DSA), and
{{?I-D.ietf-lamps-pq-composite-sigs}} (composites).  Not only must legacy
clients be supported by servers for years, new clients that support PQC are
also incented to accept traditional certificates, to retain connectivity to
legacy servers.

Once a cryptographically relevant quantum computer (CRQC) emerges publicly,
traditional certificates become insecure
and must be revoked, regardless of legacy disruption. However, a CRQC may remain undisclosed, allowing
attackers to exploit classical algorithms secretly. In such cases, adversaries could strip PQC or composite
certificates, present only traditional ones, and conduct MitM attacks. Relying parties therefore need
mechanisms to detect when servers claiming PQC support revert to traditional credentials only.

To prevent such downgrade attacks, this document defines a TLS extension that enables the
TLS client to cache an indication that the server is able to
present a (Composite or pure) PQ certificate, for some duration of time, e.g. one year. As a result:

* Clients reconnecting to an already known server within the validity period are protected
from rollback to classic certificates.
* A first-time (new) client can only learn and enforce the server's PQC commitment if its initial connection reaches the legitimate server, not an MiTM.

The explicitly communicated caching time allows clients to implement a caching policy with no risk of sudden
breakage, and allows servers to revert to traditional certificates if they ever see the need to do so.

This extension is modeled on HSTS {{?RFC6797}}, but whereas HSTS is at the HTTP layer, the extension
is implemented at the TLS layer.

On the open Web, we expect this extension to be used mainly for caching the fact that a server is
presenting a PQC or composite certificate. However, in other use cases such as service-to-service traffic,
it would often make sense to use it for both clients and servers.

An alternative approach to downgrade attacks, described in {{?I-D.reddy-lamps-x509-pq-commit}},
uses specially marked certificates to denote the server's long-term commitment
to use PQC algorithms. See {{solution-comparison}} for a comparison between the two approaches.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The pq_cert_available Extension

The following section defines a TLS extension that describes a TLS peer's commitment to present PQC
credentials.

## Extension Definition

This is a TLS extension, as per sec. 4.2 of {{!RFC8446}}. The extension type for `pq_cert_available` is TBD by IANA.
It MAY appear in the ClientHello (CH) message, CertificateRequest (CR) message and in Certificate (CT) messages sent by either client or server.

A supporting client MUST include this extension in its ClientHello message, with no extension data.

If the client indicates support, the server MAY include the extension in its Certificate message.
For symmetry, the server MAY also send an empty `pq_cert_available` extension
in the CertificateRequest to indicate support for this mechanism.
A client MUST NOT include pq_cert_available in its Certificate message unless the server has first included the extension in a CertificateRequest message.

The extension data when sent in the Certificate message is:

~~~
struct {
    SignatureScheme signature_algorithm;
    uint32 algorithm_validity_period;
}
~~~

This extension follows the format of TLS 1.3 Certificate message extensions as defined in Sec. 4.4.2 of {{RFC8446}}.

Note on terminology: Since the extension may be used by either client or server, the term "sender" is used for the peer that sent the
extension in its Certificate message and "recipient" for the other peer.

The `signature_algorithm` in this extension MUST be the signature algorithm
that the sender's end-entity certificate is associated with. `SignatureScheme` is defined by
{{RFC8446}}.

The `algorithm_validity_period` field is the time duration, in seconds, that the
sender commits to continue to present a certificate that enables this
signature scheme. The time duration is measured starting with the TLS handshake
and is unrelated to any particular certificate or its lifecycle. A value of zero 
indicates no post-handshake commitment.

## Algorithm Selection

If one of the peers holds unexpired cached information for the other peer:

   * The peer SHOULD include the cached algorithm in the `signature_algorithms` extension of its
ClientHello (or CertificateRequest for servers),
and MUST NOT include legacy (non-PQC) algorithms.
   * It MAY include other PQ signature algorithms, according to local policy.

As a result, the handshake would fail if a rollback attack is attempted.

## Recipient Behavior

A recipient that supports this extension MUST behave as follows:

1. If the recipient holds no cached information for the sender, and the sender includes a
non-empty extension:

   * The recipient SHOULD cache the provided information after the handshake is
     completed successfully and after the extension's data has been validated.
   * The recipient MAY choose to cache the signature algorithm for a shorter period than specified.

2. If the recipient holds unexpired cached information for the sender, and receives a returned extension from the sender:

   * The recipient should validate the `signature_algorithm` relative to the
     certificate being presented and SHOULD extend its cache period if the
     received time value would expire later than its current cache expiry.
   * It SHOULD NOT accept an `algorithm_validity` value if it would decrease
     its existing value (within a few seconds' tolerance).
   * It SHOULD replace its cached signature algorithm for the sender by a
     different PQ algorithm if such is sent in the extension, and in this case,
it SHOULD use the validity time as-is.

3. If the recipient holds unexpired cached information for the sender, and
   receives no returned extension from the sender, the recipient SHOULD NOT
modify its cache.

<cref>OPEN ISSUE: do we discuss how the cache is indexed? Service identity per RFC 9525?</cref>

## Sender Behavior

1. A TLS client or server that receives an indication that its peer supports this
   extension SHOULD send this extension in the Certificate message, provided a
PQ signature algorithm is used.
2. The sender MUST keep track of the time duration it has committed to, and use
   a PQ certificate to authenticate itself for that entire duration. The sender
MAY change its certificates and may switch between PQ signature algorithms at
will, provided the peer indicates acceptance of these algorithms.

This obligation is analogous to maintaining HSTS continuity: once a commitment is made,
the sender MUST avoid reverting to classical certificates until expiry of `algorithm_validity`.

## Operational Considerations

This extension establishes a (potentially) long-term commitment of the sender
to support PQ signature algorithms. As such, we recommend that deployers first
experiment with short validity periods (e.g. one day), and only when satisfied
that peers populate and depopulate their cache correctly, they can move to a longer
duration. In the case of HSTS, lifetimes are commonly set to one year.

# Security Considerations

TODO Security


# IANA Considerations

IANA is requested to assign a new value from the “TLS ExtensionType Values”

| Value | Extension Name    |  TLS 1.3  | Recommended | Reference     |
| ----: | ----------------- |  :-----:  | :---------: | :------------ |
|   TBD | pq_cert_available | CH, CR,CT |      Y      | This document |


# Document History

RFC Editor: please remove before publication.

## draft-sheffer-tls-pqc-continuity-00

Initial version.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


--- back

# Comparison with the Certificate-Based Solution {#solution-comparison}

This section is a comparison with an analogous solution {{?I-D.reddy-lamps-x509-pq-commit}} for the same rollback
problem, one that signals server continuity using certificates rather than the TLS connection itself.

* The certificate-based solution does not change the TLS handshake, which potentially makes adoption easier. However, changes
to the Web Public Key Infrastructure would also affect adoption.
* The certificate-based solution is independent of TLS and thus can be used by other protocols.
* Operationally, it may be harder to manage the “commitment” through certificates vs. TLS configuration.
For example, in the HSTS space, it is common to experiment first with very short durations, e.g. 1 day,
before moving to a longer commitment. This could have a significant effect on real-life adoption.
* The revocation checking aspect of the certificate-based solution relies upon other mechanisms
  (e.g. CRLs, OCSP) to also be signed with PQC/Composite. Those other RFCs and
implementations are likely to take even longer to materialize. 

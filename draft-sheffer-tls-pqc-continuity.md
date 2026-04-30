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
  RescorlaPQEmergency:
    title: "PQ emergency (Educated Guesswork)"
    target: https://educatedguesswork.org/posts/pq-emergency/
    author:
      ins: E. Rescorla
      name: Eric Rescorla

--- abstract

As the Internet transitions toward post-quantum cryptography (PQC), many TLS servers will continue supporting
traditional certificates to maintain compatibility with legacy clients. However, this coexistence introduces a significant vulnerability: an undetected rollback attack, where a malicious actor strips the PQC or Composite certificate and forces the use of a traditional certificate once quantum-capable adversaries exist.

To defend against this, this document defines a TLS extension that allows a TLS client to cache a server's declared commitment to present PQC or composite certificates for a specified duration. On subsequent connections, the client enforces that cached commitment and rejects traditional-only certificates that conflict with it. This mechanism, inspired by HTTP Strict Transport Security (HSTS) but operating at the TLS layer, provides PQC downgrade protection without requiring changes to certificate authority (CA) infrastructure.

--- middle

# Introduction {#introduction}

The migration to post-quantum cryptography (PQC) will be gradual. Servers will
likely host both traditional and PQC (or composite) certificates to maintain
compatibility: legacy clients can still connect, while updated ones benefit
from PQC authentication. The size of the legacy client base often drives the
decision to keep traditional certificates. Relevant PQC work includes
{{?I-D.ietf-lamps-dilithium-certificates}} (ML-DSA),
{{?I-D.ietf-lamps-x509-slhdsa}} (SLH-DSA), and
{{?I-D.ietf-lamps-pq-composite-sigs}} (composites). Not only must legacy
clients be supported by servers for years, new clients that support PQC are
also incented to accept traditional certificates, to retain connectivity to
legacy servers.

Once a cryptographically relevant quantum computer (CRQC) emerges publicly,
traditional certificates become insecure
and must be revoked, regardless of legacy disruption. However, a CRQC may remain undisclosed, allowing
attackers to exploit classical algorithms secretly. In such cases, adversaries could strip PQC or composite
certificates, present only traditional ones, and conduct MitM attacks. Relying parties therefore need
mechanisms to detect when servers claiming PQC support revert to traditional credentials only.

{{RescorlaPQEmergency}} is an informal, accessible description of the threat
of CRQC emergence and the difficulties of mounting a coordinated response.

To prevent such downgrade attacks, this document defines a TLS extension that enables a
TLS client to cache an indication that the server is able to
present a (composite or pure) PQC certificate, for some duration of time, e.g. one year. As a result:

* Clients reconnecting to an already known server within the validity period are protected
from rollback to classic certificates.
* A client begins enforcing the server's PQC commitment only after it has
  successfully connected to the legitimate server at least once (i.e., a connection
  not intercepted by a MitM). Earlier connections that are
  intercepted or downgraded do not prevent the client from gaining protection
  once it later observes a PQC commitment from a legitimate server.

The explicitly communicated caching time allows clients and server operators to implement a caching policy with no risk of sudden
breakage, and allows certificate holders to revert to traditional certificates if they ever see the need to do so.

This extension is modeled on HSTS {{?RFC6797}}, but whereas HSTS is at the HTTP layer, this extension
is implemented at the TLS layer.

Normative requirements in this document apply to TLS clients caching server commitments only.
A symmetric design (TLS servers caching client certificate commitments in mutual TLS) is not specified here since it would add significant complexity and we believe this complexity is not justified in most use cases.

An alternative approach to downgrade attacks, described in {{?I-D.reddy-lamps-x509-pq-commit}},
uses specially marked certificates to denote the server's long-term commitment
to use PQC algorithms. See {{solution-comparison}} for a comparison between the two approaches.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The pq_cert_available Extension

The following section defines a TLS extension that describes a server's commitment to present PQC
credentials to clients that support this mechanism.

## PQC end-entity certificate {#pqc-ee}

For this document, a PQC end-entity certificate is one that is not traditional-only: the EE signature employs post-quantum cryptography, whether as a pure PQ algorithm (for example PKIX profiles in {{?I-D.ietf-lamps-dilithium-certificates}} and related LAMPS work) or as a composite PQ algorithm {{?I-D.ietf-lamps-pq-composite-sigs}}. Pure PQ and composite PQ are treated identically by this document. Which EE certificates satisfy that classification in a deployment is left to client policy; this text is informative context, not a closed list of algorithms.

## Certificate chain {#certificate-chain}

Post-quantum authentication requires signatures along the entire path to be resistant to quantum-capable adversaries; a PQC end-entity certificate paired with a classically signed intermediate does not provide this property. For a fully PQ-signed path through the PKI, trust anchors would also need to be PQ-capable where they participate in validation; this document does not specify trust-store policy, and many deployments will continue to rely on classical roots.

When the client requires a PQC end-entity certificate for that handshake (including because the server sends non-empty `pq_cert_available` extension data on the first `CertificateEntry`, or because the client holds unexpired cached information for this server per Client behavior), the client MUST apply its PQC policy to every `CertificateEntry` in the server's `Certificate` message using the same criterion as in {{pqc-ee}}. If any `CertificateEntry` does not satisfy this requirement, the client MUST abort the handshake with a `certificate_unknown` alert.

## Extension Definition

This is a TLS extension, as per sec. 4.2 of {{!RFC8446}}. The extension type for `pq_cert_available` is TBD by IANA.
It MAY appear in the ClientHello (CH) message and in the server's Certificate message.

A supporting client MUST include this extension in its ClientHello message, with no extension data.

If the client indicates support, the server MAY include the extension in its Certificate message.

The extension data when sent in the server's Certificate message is either empty (no octets) or:

~~~
struct {
    uint32 algorithm_validity_period;
}
~~~

This extension follows the format of TLS 1.3 Certificate message extensions as defined in Sec. 4.4.2 of {{RFC8446}}.


The `algorithm_validity_period` field is the time duration, in seconds, that the
server commits to continue to present a PQC end-entity certificate. The time duration is measured starting from the current TLS handshake
and is unrelated to any particular certificate or its lifecycle. A duration of zero indicates no positive commitment (not a new validity window). When the end-entity certificate is PQC, that is how the server withdraws a prior commitment (see Client behavior).

A client that receives `pq_cert_available` in the server's Certificate message MUST reject extension data whose length is neither zero nor four octets; it MUST abort the handshake with a `decode_error` alert.

A server that receives `pq_cert_available` in the ClientHello MUST reject extension data whose length is not zero; it MUST abort the handshake with a `decode_error` alert.

In the server's Certificate message, `pq_cert_available` MUST appear only in the `extensions` field of the first `CertificateEntry` (the end-entity certificate) {{!RFC8446}}. A server MUST NOT attach this extension to any other `CertificateEntry`. A client that finds `pq_cert_available` on any other `CertificateEntry` MUST abort the handshake with an `illegal_parameter` alert.

## Cache indexing {#cache-indexing}

The client MUST key each cache entry by the authenticated TLS server identity from {{!RFC9525}}, the port, and whether the handshake is connection-oriented (TLS) or datagram (DTLS). Entries that differ in any of these MUST NOT be merged.

## Algorithm Selection

If the client holds unexpired cached information for the server:

   * The client MUST NOT offer legacy-only values in `signature_algorithms`: it MUST include one or more PQC-capable schemes.
   * It SHOULD include schemes consistent with enforcing the commitment, e.g. those it derived from the server's certificate on a prior connection or those it uses for this cache entry, all subject to local policy.
   * It MAY include additional PQC signature algorithms according to local policy.

As a result, the handshake would fail if a rollback attack is attempted.

## Client behavior

A client that supports this extension MUST behave as follows:

1. If the client holds no cached information for the server, and the server includes a
non-empty extension:

   * If the `algorithm_validity_period` is zero, the client MUST NOT cache the information.
   * Otherwise, the client SHOULD cache the commitment after the handshake completes successfully.
   * The client SHOULD record the server's actual signature algorithm for subsequent ClientHello `signature_algorithms` selection.
   * The client MAY choose to cache for a shorter period than specified.

2. If the client holds unexpired cached information for the server, and receives the extension from the server:

   * If the `algorithm_validity_period` is zero, the client MUST clear the cached information for this server.
   * Otherwise, the client SHOULD validate that the end-entity certificate remains PQC, that every `CertificateEntry` satisfies {{pqc-ee}}, and SHOULD extend its cache period if the
     received time value would expire later than its current cache expiry.
   * It SHOULD silently ignore an `algorithm_validity_period` value if it would decrease
     its existing cached expiry.

3. If the client holds unexpired cached information for the server, and
   receives no extension from the server in the Certificate message, the client SHOULD NOT
modify its cache.

## Server behavior

1. A server that receives client support for this extension SHOULD send this extension in the `extensions` field of the first `CertificateEntry` only when it uses a
PQC signature algorithm.
2. The server MUST keep track of the time duration it has committed to, and use
   a PQC certificate to authenticate itself for that entire duration. The server
MAY change its certificates and may switch between PQC signature algorithms at
will, provided the client indicates acceptance of these algorithms.

This obligation is analogous to maintaining HSTS continuity: once a commitment is made,
the server MUST avoid reverting to classical certificates until expiry of `algorithm_validity_period`.

If a traditional (non-PQC) certificate is used, the server SHOULD send the extension with no extension data on the first `CertificateEntry` only. If a PQC certificate is used, the server MUST send exactly the four-octet `algorithm_validity_period` on the first `CertificateEntry` only (not an empty extension).

When the server sends non-empty `pq_cert_available` extension data on the first `CertificateEntry`, every `CertificateEntry` in the server's `Certificate` message MUST be PQC under the same definition as in {{pqc-ee}}.

# Operational Considerations

This extension establishes a (potentially) long-term commitment of the server
to support PQC signature algorithms. As such, we recommend that deployers first
experiment with short validity periods (e.g. one day), and only when satisfied
that clients populate and depopulate their cache correctly, they can move to a longer
duration. In the case of HSTS, lifetimes are commonly set to one year.

Advertising `algorithm_validity_period` of zero does not clear every client's cache at the same instant. Clients that never complete another handshake to this server keep enforcing until their earlier cached expiry or until they observe zero on a completed handshake. Operators should assume overlap up to the longest validity they previously published while clients may still have been caching.

## CDNs and changing certificate chains

The same logical server (same DNS name and application identity) may present different certificate chains over time, for example when using a CDN with different points of presence, or multiple CAs. Cache entries are keyed by authenticated server identity ({{cache-indexing}}), not by a particular chain. Operators SHOULD ensure that every chain presented while a non-empty commitment is in effect satisfies {{certificate-chain}} when PQC is required.

## TLS-terminating intermediaries

Enterprise inspection proxies are common in practice: they terminate TLS toward the client and present a certificate issued under a locally trusted CA rather than the origin's Web PKI chain. The same normative constraint applies to any on-path endpoint that is not operated by the origin but presents a server `Certificate` message to the client.

An endpoint that terminates TLS toward the client and is not operated by the origin MUST NOT send non-empty `pq_cert_available` extension data unless it presents a PQC end-entity certificate chain toward the client that satisfies {{certificate-chain}} and can honor the commitment for `algorithm_validity_period` on that client-facing connection. Otherwise it MUST NOT inject a non-empty commitment on behalf of the origin.

Many TLS clients only ever connect over paths validated with public Web PKI; for them, the rules elsewhere in this document apply without additional policy. Clients that are configured to trust an enterprise or security appliance for inspection typically see most or all origins through that appliance unless the deployment makes an explicit exception; the user or organization has already accepted that the appliance terminates TLS and can present its own certificates. Implementations in such environments MAY choose how to cache or enforce `pq_cert_available` when validation uses only inspection roots---for example by not applying a commitment recorded on an inspection path when the same name is later reached on a direct Web PKI path, or by accepting traditional chains when the path chains only to inspection CAs. This document does not mandate those details. HTTP Public Key Pinning {{?RFC7469}} (Historic) described an analogous exception in Section 2.6: user agents could disable pin validation when the validated chain terminated at a user-defined trust anchor rather than a built-in anchor.

# Security Considerations

## First connection and cached state

Protection against downgrade applies only after the client has completed a handshake to the legitimate server and recorded a commitment (see {{introduction}}). Until then, behavior matches the usual trust-on-first-use limitation of channel-based pinning, analogous to HTTP Strict Transport Security (HSTS) {{?RFC6797}}: an active adversary who controls an earlier connection can prevent useful cache population or cause the client to store parameters chosen by the adversary. Cached entries are only as reliable as the authenticated channel that produced them.

Operationally, the damage is limited. If cache population is suppressed, the client would realize that the server is PQC-capable as soon as it connects directly to the server.

## Cache churn and denial of service

A malicious or compromised server can send a different `algorithm_validity_period` (or alternate between zero and non-zero values) on every successful handshake, causing the client to update persistent cache state repeatedly. That can amplify storage I/O and resource use and become a denial-of-service vector against the client. Implementations SHOULD rate-limit or coalesce cache updates per server key (see {{cache-indexing}}), and SHOULD avoid writing to durable storage when the effective commitment or expiry does not meaningfully change.

## Related threats

This mechanism does not replace PKIX validation, name verification, or trust anchor policy; it adds downgrade protection once a legitimate commitment has been observed. Mixed or invalid certificate chains remain out of scope except where this document already requires rejection (see {{certificate-chain}}).

# IANA Considerations

IANA is requested to assign a new value from the “TLS ExtensionType Values” registry.

| Value | Extension Name    |  TLS 1.3  | Recommended | Reference     |
| ----: | ----------------- |  :-----:  | :---------: | :------------ |
|   TBD | pq_cert_available | CH, CT |      Y      | This document |


# Document History

RFC Editor: please remove before publication.

## draft-sheffer-tls-pqc-continuity-03

* Certificate chain: mixed (PQC EE with non-PQC issuer chain) MUST be rejected; `certificate_unknown` (GitHub #6).
* Security Considerations: first-connection trust, cache churn / DoS (GitHub #18).
* Operational: CDNs; TLS-terminating intermediaries (commitment injection, optional client behavior) (GitHub #7).

## draft-sheffer-tls-pqc-continuity-02

Implemented comments received on the mailing list and learnings from an implementation.

* Normative scope: TLS clients caching server commitments only; cache indexing (RFC 9525). Informative note on out-of-scope symmetric use case.
* Certificate extension: `algorithm_validity_period` only (GitHub #9).
* Malformed extension length: `decode_error` (GitHub #11).
* EE-only Certificate extension placement; commitment inconsistent with non-PQC EE: `illegal_parameter` (GitHub #12).
* Cache key: RFC 9525 identity, port, TLS vs DTLS (GitHub #13).
* Remove "few seconds" tolerance when decreasing cached validity (GitHub #15).
* `algorithm_validity_period` zero: withdrawal semantics; stale-cache operations (GitHub #16).
* Define PQC EE cert: pure PQ and composite PQ one class (GitHub #17).

## draft-sheffer-tls-pqc-continuity-01

* Language consistency improvements (terminology, field names, formatting).
* Technical consistency improvements (bidirectional scope, cache semantics, validation requirements).

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

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

normative:

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Migration Scenarios

This appendix describes a likely migration scenario as different parts of the industry move at different rates from TLS with traditional crypto, into TLS with composite certificates and eventually TLS with "pure" PQ certificates. We then define a small TLS extension designed to secure TLS connections from rollback attacks during parts of this migration.

## Migration Phases

Following we list a likely chronological progression from today’s predominantly classical ecosystem to one using exclusively post-quantum (PQ) certificates. Based on our collective experience with TLS version migration and the PKI migration from RSA to ECDSA, we expect each phase to be measured in years.

1. Most TLS implementations start by adopting hybrid key exchange. As of this writing, the relevant drafts are nearly finalized, making this adoption feasible. Moreover, there is already good client-side adoption in the open Web.
2. Next, composite certificates become available for some portion of the server population.
3. Clients start using these certificates, and the common policy is "I would trust a server that presents either a traditional or a composite certificate".
4. Once the industry has reached a high percentage of Composite adoption on the client side, and trust in pure PQ is established, servers may begin presenting both Composite and pure PQ certificates.
5. Clients can then be configured to reject traditional certificates.
6. Finally, as PQ certificate adoption increases on the server side, clients can be configured to accept only pure PQ certificates.

We expect cryptography-relevant quantum computers (CRQC) to become available, at least in small quantities, sometime during this timeline. It is likely that early ones will be kept secret by state actors.

If this happens during phases (3) and (4), clients would be vulnerable to rollback attacks by a CRQC that can generate a fake traditional certificate. This vulnerability would exist despite the use of hybrid key exchange, and even if the majority of servers have already adopted Composite certificates. The next section proposes a TLS extension to mitigate this issue.

We believe that similar migration phases, similar risks and similar mitigations apply to the Dual Certificate scheme.

## The pq_cert_available Extension

The extension we define enables the TLS client to cache an indication that the server is able to present a (Composite or pure) PQ certificate, for some duration of time, e.g. one year. As a result:

* Clients that reconnect to an already known server within the validity period are protected from rollback to classic certificates.
* "New" clients are protected as soon as they connect to a server that is not fronted by a MITM attacker.

The explicitly communicated caching time allows clients to implement a caching policy with no risk of sudden breakage, and allows servers to revert to classic certificates if they ever see the need to do so.

This extension is modeled on HSTS {{?RFC6797}}, but whereas HSTS is at the HTTP layer, our extension is implemented at the TLS layer.

On the open Web, we expect this extension to be used mainly for caching the fact that a server is presenting a PQ certificate. However in other use cases such as service-to-service traffic, it would often make sense to use it for both clients and servers.

### Extension Definition

This is a TLS extension, as per sec. 4.2 of {{!RFC8446}}. The extension type for `pq_cert_available` is TBD by IANA.

It MAY appear in the Client Hello (CH) and Certificate (CT) messages sent by either client or server.

A client that supports this extension MUST send it in Client Hello, with an empty extension data.

Once a client asserted its support, the server MAY include the extension along with the certificate it presents. A client MUST NOT use this extension in the Certificate message if the server did not include it in its own Certificate message.

The extension data when sent in the Certificate message is:

~~~
struct {
    SignatureScheme signature_algorithm;
    uint32 algorithm_validity;
}
~~~

For symmetry, a server MAY send an empty `pq_cert_available` extension in its Certificate message to signal support for this mechanism, even if no signature algorithm or duration is specified.

Note on terminology: Since the extension can be sent by both client and server, in the following text we will use the term "sender" for the peer that sent the extension in its Certificate message and "recipient" for the other peer. We use `signature_algorithm` for the respective extension sent in the Client Hello message or for the equivalent extension sent within the server's CertificateRequest message.

The `signature_algorithm` in this extension MUST be the signature algorithm that the sender's certificate is associated with.

The `algorithm_validity` field is the time duration, in seconds, that the sender commits to continue to present a certificate that addresses this signature scheme. The time duration is measured starting with the TLS handshake and is unrelated to any particular certificate or its lifecycle.

### Recipient Behavior

A recipient that supports this extension MUST behave as follows:

1. If the recipient holds no cached information for the sender, and the sender includes it:

   * The recipient SHOULD cache the provided information after the handshake is completed successfully and after the extension's data has been validated.
   * The recipient MAY choose to cache the signature algorithm for a shorter period than specified.

2. If the recipient holds unexpired cached information for the sender:

   * The recipient SHOULD include the cached algorithm in its `signature_algorithms` list.
   * It MAY include other PQ signature algorithms.
   * Most importantly, it MUST abort the handshake if the sender does not present a certificate associated with one of the requested algorithms.

3. If the recipient holds unexpired cached information for the sender, and receives a returned extension from the sender:

   * The recipient should validate the `signature_algorithm` relative to the certificate being presented and SHOULD extend its cache period if the received time value would expire later than its current cache expiry.
   * It SHOULD NOT accept an `algorithm_validity` value if it would decrease its existing value (within a few seconds' tolerance).
   * It SHOULD replace its cached signature algorithm for the sender by a different PQ algorithm is such is sent in the extension, and in this case, it SHOULD use the validity time as-is.

4. If the recipient holds unexpired cached information for the sender, and receives no returned extension from the sender, the recipient SHOULD NOT modify its cache.

OPEN ISSUE: do we discuss how the cache is indexed? Service identity per RFC 9525?

### Sender Behavior

1. A TLS client or server that receives indication that its peer supports this extension SHOULD send this extension in the Certificate message, provided a PQ signature algorithm is used.
2. The sender MUST keep track of the time duration it has committed to, and use a PQ certificate to authenticate itself for that entire duration. The sender MAY change its certificates and may switch between PQ signature algorithms at will, as long as the peer indicates acceptance of these algorithms.

### Operational Considerations

This extension establishes a (potentially) long-term commitment of the sender to support PQ signature algorithms. As such, we recommend that deployers first experiment with short validity periods (e.g. one day), and only when satisfied that peers populate and depopulate their cache correctly, can move to a longer duration. In the case of HSTS, the industry has settled on 1 year as a common value.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

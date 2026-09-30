# The Negotiation Function of Hybrid PQ Key Exchange: Observations of Real Client and Server Policies

- Author: whiteclover0542
- Updated: 2026-09-30
- Data: 726 formal runs (the earlier 687, plus 24 runs of the extended real default-client survey and 15 runs of the Botan C3 server-type control) and 20 auxiliary runs
- This is an English translation of `docs/PAPER.md` (Korean). If the two differ, the Korean version is authoritative.

## Abstract

The downgrade resilience of hybrid key exchange guarantees that an attacker cannot weaken the normally negotiated result, but it does not guarantee that this normal result is hybrid. We call the rule that determines this result the **negotiation function**, and we distinguish **downgrade** caused by attacker manipulation, **PQ omission** arising from a C2 client that prefers the hybrid or from a server policy mismatch, and **client-preferred classical negotiation**, in which the client itself prefers a classical group. Five TLS servers configured hybrid-first (OpenSSL, BoringSSL, Go, NSS, rustls) split into three types: key-share-first, client-order, and server-order. The key-share-first type (OpenSSL single tuple, NSS) gave C2 a classical group without a HelloRetryRequest (HRR), and we reproduced OpenSSL CVE-2026-2673 with causal isolation in the 3.5 and 3.6 lines by applying and removing only the `ssl/t1_lib.c` fix on the `DEFAULT` expansion path. Among 16 default-configured clients (14 libraries and tools, 2 headless browsers), none was C2. All 60 on-path manipulation runs ended in connection failure, and the measured default and verbose tool outputs raised no automatic warning. The confirmed defect therefore belongs to OpenSSL alone, but the structure in which actual PQ use depends on each implementation's negotiation function and on the client's key-share strategy was observed in the five TLS implementations tested.

## 1. Introduction

Hybrid key exchange is a transition-period approach that combines a classical and a PQ algorithm so that the session key stays protected as long as either one is secure [2, 3]. Downgrade resilience, the property that an attacker cannot force a weaker mode than the one the two parties would normally negotiate, has been formalized at the design level [9]. A proof that binding the hybrid combination to the handshake transcript prevents downgrade has also been presented in a preprint [10]. Because of these results, operators easily assume that enabling a standard hybrid configuration applies PQ protection.

Yet the reference point of downgrade resilience is the result the two parties would normally negotiate without an attacker [9]. The proofs only guarantee that an attacker cannot weaken that result; they say nothing about whether that result is hybrid. It depends on what the client advertises, which key shares it sends first, and by which rule the server chooses a group. OpenSSL CVE-2026-2673, disclosed in March 2026 [5, 6], showed that a defect in this selection process alone, with no attacker, can silently turn a hybrid into a classical group.

This study measures this gap in six implementations. We keep the research questions from the planning stage unchanged.

- **RQ1.** When an on-path attacker manipulates the negotiation, do real implementations prevent downgrade as the proofs guarantee?
- **RQ2.** Without an attacker, can the hybrid silently drop out between a client and server that both support it? Does this show up in standard audit outputs?
- **RQ3.** Is it an accidental bug of a particular library that a negotiation-logic defect leads to a hybrid PQ downgrade, or a general pattern across implementations?

The "downgrade" of RQ3 is planning-stage wording; in this paper's terminology it corresponds to PQ omission (§2.1).

The "standard audit outputs" of RQ2 are limited to the default and verbose tool outputs measured in this paper (§5.3, §6.5).

Our contributions are as follows.

1. We compare the negotiation functions of five TLS server implementations under identical conditions, show that three selection types exist even with a hybrid-first configuration (key-share-first, client-order, server-order), and confirm from source code the types of the two implementations whose selection rules are not publicly documented (BoringSSL, NSS) (§6.1).
2. Using six default-configured clients, two headless browsers, and two server packages (nginx, Caddy), we examine whether the C2-type PQ omission condition holds under defaults (§6.2).
3. We reproduce an OpenSSL defect in which the server fails to keep its own policy (CVE-2026-2673) and confirm it in both the 3.5 and 3.6 lines by causal isolation that applies and removes the fix code (§6.3).
4. We present a comparison of three implementations × on-path fault types and identify at which defense layer each rejection happened (transcript binding, exchange-hash signature, key-format validation) (§6.4).
5. We show that the measured default TLS audit outputs neither warn about nor reveal C2-type PQ omission and the CVE policy mismatch, and that verbose outputs show the material for judgment but do not warn (§6.5).

## 2. Background

### 2.1 Terminology: negotiation function, downgrade, PQ omission, client-preferred classical negotiation, PQ non-use

In this paper, the **negotiation function** is the rule that, given both parties' configurations and implementations, determines which group is negotiated without an attacker. A **downgrade** is an attacker manipulating messages to force a mode weaker than the negotiation function's result [9]. C2 in Table 1 (§5.2) is the type that prefers the hybrid over the classical group but sends only a classical initial key share, and C3 is the type that prefers the classical group first. E4 is a control experiment that advertised the classical group first (Appendix C). **PQ omission** is the case where a classical group is chosen without an attacker and either (a) the client is C2, or (b) the server chose the classical group contrary to its documented or configured hybrid-first policy. The former can be behavior according to rules an implementation states in its documentation or source (§6.1); the latter can be a defect in which the implementation breaks its own policy (§6.3). **Client-preferred classical negotiation** is the case, as with C3 and E4, where the client prefers the classical group first and the classical group is chosen. Even when the hybrid is supported, we classify this as normal negotiation, neither PQ omission nor downgrade. When one side does not support the hybrid, or does not advertise or select it under default settings, so that the condition of both sides using the hybrid does not hold at all, we call it **PQ non-use** (§6.2, §6.2.1).

### 2.2 Key exchange negotiation in TLS 1.3 and SSH

A TLS 1.3 client advertises its supported groups in `supported_groups` and sends key material for some of them in advance in `key_share` [1]. The server chooses a group. If a key share for the chosen group has already arrived, it replies with a ServerHello; if the group is mutually supported but has no key share, it asks again with an HRR. RFC 8446 requires an HRR when no compatible key share exists, but does not require an HRR for a more preferred group when a compatible key share is already present, and leaves the group selection criteria to implementations. Because the handshake keys are derived from all messages so far (the transcript), changing a message in transit makes the two sides' keys differ and the connection fails. An HRR uses the same format as a ServerHello and is distinguished only by a fixed random value.

SSH chooses, from the KEX algorithm lists both sides send, the first algorithm in the client's list order that both share [13]. Unlike TLS, the selection rule is fixed by the specification. The server signs, with its host key, an exchange hash that includes the key exchange result and both sides' negotiation messages.

### 2.3 Hybrid groups

`X25519MLKEM768` is a TLS hybrid group that combines ML-KEM-768 and X25519 [3]. It concatenates the public values and shared secrets of the two components and feeds them into the key schedule [2]. A hybrid key share is much larger than a classical one. A client can therefore send only a classical group as its initial key share and send the hybrid only when the server asks. The advisory names such clients as the trigger condition of CVE-2026-2673 [5].

### 2.4 Group tuples and `DEFAULT` in OpenSSL 3.5

In an OpenSSL 3.5 server group list, `:` separates groups inside the same priority bundle (tuple) and `/` marks a tuple boundary [4]. The server examines tuples from the most preferred. If a key share already received is in the current tuple, it replies with a ServerHello; if only a supported group is there, it replies with an HRR. The built-in default list puts the hybrid group in its own first tuple. CVE-2026-2673 is a defect in which this tuple boundary disappears when the `DEFAULT` keyword in a configuration string is expanded [5, 7, 8].

## 3. Related work

Bhargavan et al. formalized downgrade in configurable key-exchange protocols and analyzed the conditions for downgrade resilience [9]. Gupta and Rana presented, in a preprint, a proof that a transcript-bound combiner prevents downgrade in hybrid PQ key establishment [10]. FREAK is a case where an implementation defect in the TLS state machine [11], and Logjam a case where a protocol-level weakness, support for export-grade Diffie-Hellman [12], led to real downgrade attacks. These works address an on-path attacker manipulating the negotiation. We measure the same case in real PQ hybrid implementations (RQ1) and, in addition, measure in implementations the negotiation function itself that the proofs take as their reference (RQ2, RQ3). This does not conflict with the proofs; it examines what the proofs assume.

Deployment and specification sources address the same point. Benjamin's key share prediction draft explains that because a client sends key shares for only some of its `supported_groups`, the remaining groups need an HRR, and that PQ KEMs have large keys, which makes this cost pronounced [21]. Its security considerations list what a server may weigh when choosing a group (its own preference, the client's preference, presence in key_share), state that presence in key_share should be the criterion only when the two groups have comparable preference, and recommend that "Servers SHOULD NOT use key_share to select a classical named group over a post-quantum named group" [21, Section 4]. This draft is an Internet-Draft that expired in September 2026 and is not normative. Wickramasinghe et al. tracked 684,494 domains out of the top one million that completed TLS 1.3 from every vantage point in all three measurement rounds, and reported that the share negotiating `X25519MLKEM768` by default in a handshake advertising all groups was 31.26% in July 2025 and 49.22% in March 2026 [22]. In the same table, the share negotiated when explicitly requested (support) was almost identical to the default share (a difference of 2 domains in March 2026). In an October 2025 blog post, Cloudflare distinguished sending the PQ key share to origin servers immediately from postponing it by one HRR, and said it had turned on the latter by default for non-enterprise customers [23]. We cite these sources only as context for our measurements and did not re-measure their figures.

## 4. Threat model

- **Region A: on-path manipulation (downgrade).** The attacker can modify handshake messages between client and server but does not have the server's long-term key. A successful downgrade is a connection that would have been negotiated as hybrid without the attacker instead succeeding with a classical group. This tests the property the formal proofs guarantee.
- **Region B: negotiation without an attacker.** A normal client and a normally configured server negotiate. We measure the negotiation function and separate C2-type PQ omission from client-preferred classical negotiation.

The scope is a fixed local loopback testbed. We do not measure Internet-scale deployment frequency, and for browsers we examine only the default ClientHello of two headless builds.

## 5. Method

### 5.1 Testbed

All experiments ran on loopback in WSL Ubuntu. The negotiation-function comparison (E8) used OpenSSL 3.5.6, BoringSSL (2024-08 build `7fb4d3d`, using `X25519MLKEM768`), a minimal server written with Go 1.26 `crypto/tls`, NSS 3.120 `selfserv`, and a minimal server written with rustls 0.23.45 (aws-lc-rs). The default survey (E9) used a source-built OpenSSL 3.5.5 `s_client`, BoringSSL `bssl client` (the same 2024-08 build), Ubuntu packages (curl 8.18.0 with the system OpenSSL 3.5.5-1ubuntu3.5, NSS 3.120 `tstclnt`, nginx 1.28.3, Caddy 2.6.2), and minimal Go and rustls clients. The browser survey (E10) ran the `chrome-headless-shell` of Chrome for Testing 154.0.8037.57 and the official Firefox 156.0.1 release headless. The CVE case (E5–E7) used source builds of OpenSSL 3.5.5, 3.5.6, 3.6.1, 3.6.2 and four patched variants, and on-path manipulation (E1–E3) used fixed builds of OpenSSL 3.5.5 (with oqs-provider 0.9.0), BoringSSL, and OpenSSH portable. Because the behavior is deterministic, E1–E7 were repeated 10 times, E8 5 times, and E9, E10 and the `-trace` reruns 3 times.

### 5.2 Experiments

**Table 1.** Client types in TLS negotiation without an attacker

| Type | `supported_groups` preference | Initial `key_share` | Classification in this paper |
|---|---|---|---|
| C1 | Hybrid first | Includes hybrid | Hybrid negotiation baseline |
| C2 | Hybrid first | Classical only | C2-type PQ omission condition |
| C3 | Classical first | Classical only | Client-preferred classical negotiation |

The body presents only these types and the flow of results; the full experiment matrix E1–E11 is in Appendix C. C2 was produced with the OpenSSL setting `X25519MLKEM768:*X25519` (`*` marks the groups to send key shares for). All servers ran in each implementation's default selection mode, and for OpenSSL we separately tested the server-preference option (`-serverpref`). As an auxiliary condition we ran S4, which omits the OpenSSL server group setting.

### 5.3 Measurement

Each run records the negotiated group, handshake success or failure and the reason for failure, and a packet capture. An HRR was identified by whether the random of a captured ServerHello equals the RFC 8446 HRR constant. The client precondition (advertised order and key shares) was verified from the capture in every run. For manipulation experiments, the proxy log and capture confirmed that the manipulation was actually applied. The E5 reproduction verdict rule was fixed in code before collection. In S3 the affected version must negotiate `X25519` without an HRR and the fixed version `X25519MLKEM768` after an HRR, S1 and S2 must show the documented results, and each combination must be consistent across 10 runs. Agreement between the log and capture HRR verdicts and the condition of exactly one real ServerHello were added after collection while tightening the rule (the verdict was unchanged). E9a recorded only the ClientHello and the group the server chose, and did not judge per-client handshake completion (in the raw records `handshake_result` remains `failure` for non-OpenSSL clients because of output-format differences). The Caddy 2.11.4 control is the 9 Caddy C1–C3 runs among the 36 reruns of E9a and E9b; we did not connect default clients directly to the latest Caddy. Audit visibility was measured on three paths (client log, server log, default capture summary), by whether an explicit warning string appears and whether the advertised and negotiated groups can be identified together in one output. We additionally measured two verbose paths by the same criteria. We applied `tshark -V` to 537 preserved captures (E5–E10, causal isolation, latest-build controls), and reran the three E5 conditions (3.5.5 S1 and S3, 3.5.6 S3) three times each with client `s_client -trace`. Warnings in verbose output were judged by warning strings and by tshark expert information (Warning, Error) other than connection Sequence items.

## 6. Results

### 6.1 The negotiation functions of five TLS implementations (E8)

Table 2 shows 105 runs connecting the same fixed client to five TLS server implementations. Every server listed the hybrid before the classical group in its configuration. In all 105 runs the client precondition was confirmed from the capture and the handshake completed, and the 5 runs of each combination all gave the same result.

**Table 2.** Negotiation functions of five TLS server implementations (5 runs each; `HRR→hybrid` is `X25519MLKEM768` after an HRR)

| Server | Selection type | C1 hybrid first + hybrid share | C2 hybrid first + `X25519` share only | C3 classical first + `X25519` share |
|---|---|---|---|---|
| OpenSSL 3.5.6, single tuple `X25519MLKEM768:X25519` | Key-share-first | Hybrid | **Classical (no HRR)** | Classical |
| OpenSSL 3.5.6, single tuple + `-serverpref` | Key-share-first | Hybrid | **Classical (no HRR)** | Classical |
| NSS 3.120 `selfserv` | Key-share-first | Hybrid | **Classical (no HRR)** | Classical |
| BoringSSL `bssl server` | Client-order | Hybrid | HRR→hybrid | Classical |
| rustls 0.23.45 | Client-order | Hybrid | HRR→hybrid | Classical |
| Go 1.26 `crypto/tls` | Server-order | Hybrid | HRR→hybrid | **HRR→hybrid** |
| OpenSSL 3.5.6, tuple boundary `X25519MLKEM768/X25519` | Server-order | Hybrid | HRR→hybrid | **HRR→hybrid** |

With the same server configuration, results differed by implementation. The **key-share-first** type does not send an HRR if it can negotiate with a key share it already received. C2, which wants the hybrid first but deferred only its key share, therefore received a classical group. Both sides support the hybrid and the client prefers it, yet a classical group was negotiated, so this is C2-type PQ omission. In OpenSSL the result was the same with the server-preference option on. The **client-order** type follows the order the client advertised and requests the group's key share with an HRR if it is missing. The classical result for C3 is client-preferred classical negotiation. The **server-order** type follows the server's preference, so it negotiated the hybrid even for C3, which advertised the classical group first.

We compared the observed types with each implementation's documentation or source. OpenSSL's results matched its documented selection pseudocode [4]. The Go documentation states that "The order of the list is ignored, and key exchange mechanisms are chosen from this list using an internal preference order" [14], and the observations matched an internal preference that favors the hybrid. The rustls documentation only calls the group list "in preference order" and does not state a server-side selection rule [15]. For BoringSSL and NSS, whose selection rules we could not find in public documentation, we examined the source code.

- **BoringSSL** (2024-08 commit `7fb4d3d`, latest control commit `697ee71`): `tls1_get_shared_group` (`ssl/extensions.cc` lines 323–360) takes the client's `supported_groups` order as the preference order unless `SSL_OP_CIPHER_SERVER_PREFERENCE` is set, and picks the first common group [16]. The server first fixes the group with this function (`ssl/tls13_server.cc` line 471) and sends an HRR if that group's key share is missing (lines 478–479 and 581–586 of the same file). The latest control, 3 runs each of C1–C3, gave the same results as the 2024-08 build, so both test points match the client-order type.
- **NSS** (3.120 release tag): `tls13_NegotiateKeyExchange` (`lib/ssl/tls13con.c`) takes the first group in the server's preference list as the preferred group and, if that group has no key share, looks at the next group's key share. If that group passes `tls13_isGroupAcceptable`, that is, its strength (bits) is within ±2 bits of the preferred group, it takes that group without an HRR (lines 2016–2033 and 2091–2128) [17]. `lib/ssl/sslsock.c` defines both `X25519MLKEM768` and X25519 as 256 bits (lines 170–171). NSS therefore judges X25519 an acceptable substitute for the hybrid. This strength comparison does not take PQ into account. The observed key-share-first type is the result of this rule.

### 6.2 Default-configured clients and real servers (E9)

The C2-type PQ omission of §6.1 appeared for a client that prefers the hybrid but defers its key share. E9a examined whether default-configured clients meet this condition (Table 3, 18 runs).

**Table 3.** ClientHello of default-configured clients (3 runs each, all identical; the server is OpenSSL 3.5.6 with default settings)

| Client | Start of `supported_groups` | Initial `key_share` | Negotiated group |
|---|---|---|---|
| OpenSSL 3.5.5 `s_client` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| curl 8.18.0 (system OpenSSL 3.5.5) | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| Go 1.26 `crypto/tls` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| rustls 0.23.45 | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| NSS 3.120 `tstclnt` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768` | `X25519MLKEM768` |
| BoringSSL `bssl client` (2024-08 build) | `X25519`, P-256, P-384 | `X25519` | `X25519` |

All five clients that advertised the hybrid also sent a hybrid key share in their first ClientHello. Under default settings they were C1, and in E8 C1 received the hybrid from all five servers. None of the default clients tested met the PQ omission condition (C2). The 2024-08 BoringSSL build did not advertise the hybrid by default. This is that build's default; we did not measure current BoringSSL defaults.

In E10 the two browsers gave the same result (3/3 runs each). Headless Chrome 154 advertised a GREASE value [20], `X25519MLKEM768`, `X25519`, P-256, P-384 in that order and sent GREASE, `X25519MLKEM768` and `X25519` key shares. Firefox 156 advertised `X25519MLKEM768`, `X25519`, P-256, P-384, P-521 in that order and sent `X25519MLKEM768`, `X25519` and P-256 key shares. Both browsers were C1, and the server negotiated the hybrid without an HRR. The browsers tested are headless builds; we did not check the settings of regular releases or mobile builds.

E9b started the server packages with default settings and connected the same fixed clients C1–C3 as in E8 (Table 4, 18 runs). In all 18 runs the client precondition was confirmed from the capture and the handshake succeeded.

**Table 4.** Default-configured server software (3 runs each, all identical)

| Server | C1 hybrid first + hybrid share | C2 hybrid first + `X25519` share only | C3 classical first + `X25519` share |
|---|---|---|---|
| nginx 1.28.3 (system OpenSSL 3.5.5) | Hybrid (no HRR) | HRR→hybrid | HRR→hybrid |
| Caddy 2.6.2 | **HRR→`X25519`** | Classical (no HRR) | Classical (no HRR) |

Without a group setting, nginx uses OpenSSL's built-in default list, which puts the hybrid in its own first tuple (§2.4). It therefore behaved as the server-order type and negotiated the hybrid even for C3. The C3 control ended in server-preferred hybrid negotiation, and default nginx showed no C2-type PQ omission. Caddy 2.6.2 answered C1, which sent only a hybrid key share, with an HRR requesting an X25519 key share, and negotiated classical groups with all three clients. This version did not choose the hybrid under default settings. Its `go version -m` output still carries Go 1.25.0's `tlsmlkem=0`. This behavior is not the result of the negotiation function comparing the hybrid with other groups, so in this paper's terminology it is PQ non-use, not PQ omission.

E9c is 36 runs connecting default-configured clients directly to default-configured servers (Table 5). nginx negotiated X25519 with BoringSSL and the hybrid with the other five clients. Caddy 2.6.2 negotiated X25519 with BoringSSL, OpenSSL, curl, Go and NSS. The three rustls–Caddy connections failed without a ServerHello; the client and server logs held no error that identifies the cause, so we do not claim an SNI, certificate or ALPN cause.

**Table 5.** Default clients × default servers, direct connection (3 runs each)

| Server | X25519 | `X25519MLKEM768` | Failure |
|---|---:|---:|---:|
| nginx 1.28.3 | BoringSSL 3/3 | OpenSSL, curl, Go, NSS, rustls 3/3 each | 0/18 |
| Caddy 2.6.2 | BoringSSL, OpenSSL, curl, Go, NSS 3/3 each | 0/18 | rustls 3/3 |

In the control with the official Caddy 2.11.4 (Go 1.26.3), the fixed C1 negotiated the hybrid without an HRR and C2 and C3 after an HRR, 3/3 runs each. Because both the Caddy and Go versions differ between Caddy 2.6.2 and 2.11.4, we do not make the causal claim that `tlsmlkem=0` is the sole cause of the difference. The built-in Go default of Caddy 2.6.2 and the latest control result are, however, consistent with the description of Go's TLS ML-KEM default [18, 19].

### 6.2.1 Extended real defaults and the Botan C3 policy control (E11)

E11 examined defaults more broadly without changing any candidate's group order or key shares. In the 24 runs of Table 6 (8 candidates × 3 runs) there was no C2, that is, no default client that **puts the hybrid first but does not send a hybrid key share**. wolfSSL, s2n-tls, Node.js and Python were C1. GnuTLS, Java and mbedTLS did not advertise the hybrid and were classified as PQ non-use. Only Botan 3.10.0 was C3, advertising the hybrid third and sending only an X25519 share. Botan is therefore not C2, and this sample is not a case of a server turning a hybrid-first C2 into a classical result.

**Table 6.** ClientHello of real default clients in v1.8 (3 runs each, OpenSSL 3.5.6 default server)

| Classification | Clients | Observed `supported_groups` and `key_share` |
|---|---|---|
| C1 | wolfSSL, s2n-tls, Node.js, Python | Hybrid in the first group and the initial shares |
| C3 | Botan 3.10.0 | `X25519`, P-256, `X25519MLKEM768`, … / `X25519` share only |
| PQ non-use | GnuTLS, Java, mbedTLS | No hybrid in default `supported_groups` |

The 15-run server-type control of Botan C3 showed X25519 without an HRR, 3/3 each, on the key-share-first servers (the two OpenSSL single-tuple settings, NSS) and the client-order server (BoringSSL). In the default survey, the OpenSSL 3.5.6 default setting, a server-order type, negotiated `X25519MLKEM768` after an HRR 3/3 times, and the Go server in the 15-run control showed the same server-order result 3/3 times. The first four classical results are **client-preferred classical negotiation** by C3, whose client itself put the classical group first. They therefore show neither PQ omission, the existence of a real C2, nor a server ignoring its policy; they show only that, in this limited server sample, the C3 result depends on the selection type.

### 6.3 The CVE-2026-2673 case (E5–E7)

E5–E7 form a comparison matrix of OpenSSL server settings. Among them, the S3 `DEFAULT` result of the affected version is PQ omission in which the server failed to keep its documented tuple policy; S1 and S2 are documented control conditions. In Table 7 the classical-first client (E5) and C2 (E7) gave the same results. In each set of 60 runs the client precondition was verified and every handshake succeeded.

**Table 7.** The CVE-2026-2673 case (each cell is the same result in 10 E5 runs and 10 E7 runs)

| Server | S1 single tuple | S2 tuple boundary | S3 `DEFAULT` |
|---|---|---|---|
| 3.5.5 (affected) | HRR 0 · `X25519` | HRR 10 · `X25519MLKEM768` | **HRR 0 · `X25519`** |
| 3.5.6 (fixed) | HRR 0 · `X25519` | HRR 10 · `X25519MLKEM768` | **HRR 10 · `X25519MLKEM768`** |

The two versions differed only in S3. If the default list that puts the hybrid in the first tuple were preserved, S3 should, like S2, request the hybrid with an HRR. 3.5.5 did not. The log and capture HRR verdicts all agreed, and cross-checking two samples with a separate capture analysis tool (tshark) gave the same result. Because all predefined verdict conditions were met, we judge that this testbed reproduced the trigger condition and the fix contrast of CVE-2026-2673. In the auxiliary condition S4 (no setting), both versions negotiated the hybrid after an HRR 10/10 times. The defect appeared only on the expansion path of the `DEFAULT` keyword, not in the default list itself. The client's advertised order did not change the server's choice. The S1 result is the same as the key-share-first behavior in §6.1.

**Causal isolation (E6).** Table 8 shows S3 results for servers that differ only in whether the fix change is present. In all 180 runs (120 for the 3.5 variants and 3.6 tags, 60 for the 3.6 variants) the precondition was verified and the handshake succeeded. S1 and S2 were the same as Table 7 for all six servers.

**Table 8.** S3 results with and without the fix change (10 runs each)

| Server | Fix change | HRR | Final group |
|---|---|---:|---|
| 3.5.5-cherrypick (3.5.5 + fix change) | Present | 10/10 | `X25519MLKEM768` |
| 3.5.6-revert (3.5.6 − fix change) | Absent | 0/10 | `X25519` |
| 3.6.1 | Absent | 0/10 | `X25519` |
| 3.6.2 | Present | 10/10 | `X25519MLKEM768` |
| 3.6.1-cherrypick (3.6.1 + 3.6 fix change) | Present | 10/10 | `X25519MLKEM768` |
| 3.6.2-revert (3.6.2 − 3.6 fix change) | Absent | 0/10 | `X25519` |

Adding the fix change made the affected version behave like the fixed version, and removing it made the fixed version behave like the affected version. In the 3.6 line as well, adding only the `ssl/t1_lib.c` change of fix commit `2157c9d` to 3.6.1 made it behave like the fixed version, and removing it from 3.6.2 made it behave like the affected version. In both lines, therefore, the S3 difference is explained by this single-file change of each fix commit.

### 6.4 On-path manipulation and baseline (E1–E4)

Table 9 compares three implementations × fault types. The planning-stage comparison (E1, E2) is extended with E3 and E4 from v1.1.

**Table 9.** Results by implementation × fault type (10 runs each)

| Fault type | OpenSSL | BoringSSL | OpenSSH |
|---|---|---|---|
| E1 classical-only offer (baseline) | Success, `X25519` | Success, `X25519` | Success, `curve25519-sha256` |
| E2 PQ component tampering (A) | Failure 10/10 — key-format validation | Failure 10/10 — key-format validation | Failure 10/10 — exchange-hash signature |
| E3 hybrid removal (A) | Failure 10/10 — transcript binding | Failure 10/10 — transcript binding | Failure 10/10 — packet format error (inconclusive) |
| E4 classical-first advertisement (B) | Success, `X25519`, no HRR | Success, `X25519` | Not tested (the specification fixes the selection rule) |

The default negotiation that advertised the hybrid first succeeded with the hybrid in all three implementations (OpenSSL `X25519MLKEM768`, BoringSSL `X25519Kyber768Draft00`, OpenSSH `sntrup761x25519-sha512`, 10/10 each). The BoringSSL experiment at this stage used the earlier hybrid group `X25519Kyber768Draft00` through the harness configuration (the same build negotiated `X25519MLKEM768` in E8).

No downgrade succeeded in the 60 runs of E2 and E3. For TLS hybrid removal, transcript binding stopped it in both implementations. OpenSSL ended with `bad record mac` after an HRR, and BoringSSL, after answering with the remaining `X25519` key share, ended in a decryption failure. SSH PQ component tampering was stopped by a failed exchange-hash signature check (`incorrect signature`). These 30 runs, in which the binding layer acted directly, agree with the proofs' predictions. In contrast, TLS PQ component tampering was rejected before binding verification, by key-format validation, because the tampered value was not a valid PQ public key. The TLS combiner binding itself was therefore not tested. SSH KEX removal pushed the packet length off block alignment and ended in a format error, so the negotiation defense could not be judged. E4 is client-preferred classical negotiation without an attacker; because the client itself preferred the classical group, the classical negotiation is behavior according to the specification and each implementation's policy.

### 6.5 Audit visibility

No explicit warning appeared on any of the three paths measured in the 90 v1.1 cross-implementation runs, the 60 E5 runs and the 60 E7 runs. For TLS connections, the advertised and negotiated groups could not be identified together in one output. The OpenSSL client log shows the negotiated group by name but leaves the advertised list only as a hex dump, the BoringSSL client log does not record the advertised list, and the default capture summary has no group information. Only the OpenSSH verbose log (30 runs) showed both in one output. The connections in which the CVE defect manifested could not be distinguished from normal classical connections in the measured default outputs. Because the defect and the normal S1 behavior send the same messages, it is expected in principle that the negotiation result alone cannot tell them apart. We did not measure the default output paths of E8–E10.

The verbose outputs were different. Applying `tshark -V` to the 537 preserved captures of E5–E10, causal isolation and the latest-build controls, all 534 captures with a ServerHello showed the ClientHello's advertised groups and the ServerHello's key-share group in one output, and that group matched the negotiated group recorded by capture analysis in every case. The remaining 3 are rustls–Caddy 2.6.2 connections that ended without a ServerHello. The 9 reruns with `s_client -trace` also showed the advertised groups, both sides' key shares and the negotiated group by name. In addition, an OpenSSL server sends its own supported-group list in EncryptedExtensions only when the negotiated group is not its first choice (3.5.6 source `ssl/statem/extensions_srvr.c` lines 1667–1699). The logs of the 3.5.5 S1 and S3 connections therefore also printed a list in which the server put `X25519MLKEM768` first, and the 3.5.6 S3 runs that negotiated the hybrid did not. This list is in an encrypted message and cannot be seen in a capture without the keys. Neither verbose output contained any warning. Verbose outputs thus gather the material for judging an omission in one place, but a person or a separate tool still has to compare the advertised list with the negotiation result. This signal does not distinguish the documented S1 behavior from the S3 defect.

## 7. Discussion

Table 10 summarizes what this study showed and did not show.

**Table 10.** What this study showed and did not show

| Item | Shown | Not shown / scope |
|---|---|---|
| OpenSSL defect | In 3.5 and 3.6, the fix to `ssl/t1_lib.c` alone flips the CVE-2026-2673 S3 result | Frequency of impact in real deployments |
| TLS negotiation function | Five TLS servers with a hybrid-first configuration split into three selection types | Universal policy of other versions, settings or implementations |
| Defaults and browsers | The five default clients tested and headless Chrome and Firefox send a hybrid key share first | Key-share distribution of regular browsers, mobile, and the Internet at large |
| v1.8 real defaults | No C2 among 8 additional samples and Botan is C3; client-preferred classical negotiation results vary with the selection type of five servers | Existence and frequency of real C2, server policies of other versions and settings |
| External sources | Per public sources, a large CDN enabled, by default for non-enterprise customers as of October 2025, deferring the PQ key share on origin connections until after an HRR [23]; in an Internet measurement, nearly all servers supporting `X25519MLKEM768` chose it by default when all groups were advertised [22] | That CDN's advertised order and the origin servers' selection types; the actual PQ omission rate of C2 connections |
| Caddy | The distribution's Caddy 2.6.2 negotiates X25519 with five clients in direct connections | Single cause `tlsmlkem=0`; direct connection of default clients to the latest Caddy |
| On-path manipulation | None of the 60 runs tested ended in a successful classical negotiation; the 30 runs reaching the binding layer (TLS removal, SSH tampering) were stopped as the proofs predict | TLS combiner binding, SSH KEX-removal defense |
| Audit visibility | The measured default and verbose tool outputs do not warn automatically; verbose outputs provide material for judgment | Visibility of other implementations, server-side verbose output, key logs |

### 7.1 Where is the gap? (RQ1, RQ2)

In Region A, which the proofs guarantee, all 30 runs that reached the binding layer were stopped and the implementations behaved as the proofs predict (§6.4). We could not, however, judge the hybrid combiner binding itself or SSH's defense against KEX list removal.

The gap was in Region B. Even when a client and server that support the hybrid meet, the negotiation function decided whether the hybrid is used. The proofs only protect the negotiation function's result, so if that result is classical, they protect the classical result. PQ omission appeared through two paths. One is the result of a selection rule the specification allows and an implementation states in its documentation or source: the key-share-first type gave a classical group to C2, which prefers the hybrid (§6.1). RFC 8446 does not require an HRR when a compatible key share is already present [1]. The other is a defect in which an implementation broke its own policy (CVE-2026-2673, §6.3). The classical results of C3 and E4 are a separate client-preferred classical negotiation and are not mixed with these two. The C2-type PQ omission and the CVE connections did not show up in the measured default TLS outputs, and verbose outputs showed only the material for judgment, with no warning (§6.5). Our answer to RQ2 is "yes, and it did not show up in the default outputs."

The default surveys (§6.2, §6.2.1), however, narrow the actual extent of this gap. In the earlier defaults and browser samples, the five clients that advertised the hybrid and the two browsers all sent a hybrid key share first. The added v1.8 sample had no C2 either. Botan is C3, so it received the hybrid after an HRR from the server-order type and a classical group, as client-preferred classical negotiation, from the key-share-first and client-order types. As the advisory states, CVE-2026-2673 also manifests only with clients that defer the key share [5]. In the direct-connection sample, nginx negotiated the hybrid with the five earlier clients, and Caddy 2.6.2 negotiated X25519 with five clients and was observed as PQ non-use. Public sources point to possibilities outside this scope. In an October 2025 blog post, Cloudflare distinguished sending the PQ key share to origin servers immediately from postponing it by one HRR, and said it had turned on the latter by default for non-enterprise customers [23]. The advertised order of that mode is not public, so we could not confirm whether it is the same as our C2. If it is a client that wants a PQ group but defers the key share, we infer that key-share-first servers (OpenSSL single tuple, NSS) or servers running an affected CVE-2026-2673 version with a `DEFAULT` setting that receive those connections would choose a classical group without an HRR (§6.1, §6.3). How many hybrid-first clients that defer the key share actually exist, and which servers they meet, is a question this study does not answer.

### 7.2 Accidental bug or general pattern? (RQ3)

The defect itself belongs to a particular library. OpenSSL's result turned on and off with a single library change of the fix commit (§6.3), and the commit title ("Fix group tuple handling in DEFAULT expansion") also indicates a defect on the `DEFAULT` expansion path. The other implementations have no tuple syntax or configuration syntax equivalent to `DEFAULT`, so the same class of defect could not be tested there.

The gap through which the defect entered, however, was common across implementations. All five TLS servers listed the hybrid first, yet the negotiation functions split into three types, and two implementations (OpenSSL single tuple, NSS) gave C2 a classical group according to documented or source-stated rules. NSS's rule compared strength only by bit count and treated the hybrid and X25519 as the same. This can be seen as a selection rule made before the hybrid transition that remains unaware of PQ. The behavior of the key-share-first type giving C2 a classical group is allowed by RFC 8446 (the client may omit the key share of its most preferred group, [1] Section 4.2.8), but it departs from the key share prediction draft's recommendation not to "use key_share to select a classical named group over a post-quantum named group" [21]. Because the draft is not normative, we do not call this a violation. In OpenSSH the selection rule is fixed by the specification, the verbose log let us check the advertisement and the negotiation together, and no omission was observed. Our answer is therefore as follows. **The defect we observed is an accidental bug of one library. But the structure in which PQ protection is left to implementation discretion, depends on negotiation functions that differ between implementations, and does not show up in default outputs is a pattern across all five TLS implementations tested.** For this structure to lead to real C2-type PQ omission, there must be a hybrid-first client that defers its key share; we found none in the extended v1.8 default sample or the two browsers.

### 7.3 Practical implications

First, whether the hybrid is active cannot be confirmed from the configuration or connection success alone. The actually negotiated group has to be recorded and compared with the intended policy. Verbose outputs (`s_client -trace`, `tshark -V`) show the advertised and negotiated groups in one output and so provide material for this comparison, but they do not warn by themselves. Second, the versions of the server package and its embedded TLS runtime have to be checked together. The distribution's Caddy 2.6.2 negotiated X25519 with five clients in direct connections and contained `tlsmlkem=0`, but we have not yet isolated a single cause. Third, servers that must accept clients deferring their key share need to check their selection type. In OpenSSL, putting the hybrid in its own first tuple or using the built-in default list made the server request the hybrid with an HRR, while NSS's default rule did not choose the hybrid. Servers that receive origin connections deferring the PQ key share may also fall into this case [23]. Fourth, on affected OpenSSL versions (3.5.0–3.5.5 and 3.6.0–3.6.1 according to the CVE record [6]), using `DEFAULT` in the server group setting can end connections with clients that defer the key share in a classical group. The advisory recommends upgrading to 3.5.6 and 3.6.2 [5].

## 8. Limitations

The experiments ran on a fixed local loopback testbed. The client for E8 and E9b and the client for E5–E7 are all one OpenSSL 3.5.5. Servers were tested in each implementation's default selection mode with one server configuration (for OpenSSL we also tested the server-preference option). Go and rustls were tested with minimal programs. For BoringSSL we compared only C1–C3 between the 2024-08 build and the latest commit `697ee71`, and did not survey the latest build's default client values. We read the NSS source from the 3.120 release tag on the GitHub mirror, and confirmed that the five Ubuntu patches do not modify `tls13con.c` or `sslsock.c` directly, but could not rule out effects through other paths. We compared Caddy 2.6.2 with the official 2.11.4, but both Caddy and Go change between the two binaries, so we could not isolate the causal role of `tlsmlkem=0`. The 3 direct 2.6.2–rustls connections failed without a ServerHello, and the logs alone did not reveal the cause. We ran 36 direct connections between default clients and default servers but did not connect default clients directly to Caddy 2.11.4. Repetitions were 10 for E1–E7, 5 for E8, and 3 for the E9 series, E10 and the `-trace` reruns, and the results of the observed completed connections were deterministic.

The default surveys measured only library defaults and two headless browsers (Chrome for Testing 154, Firefox 156) on loopback. In the 8 additional v1.8 library samples there was no C2, and only one more C3 (Botan) was observed. We did not measure remote configuration of regular browser releases, mobile clients, or Internet-scale deployment frequency. We therefore cannot say how many hybrid-first clients that defer the key share actually exist. The public sources cited in §3 and §7 [21, 22, 23] are not measurements of this study, and their methods and timing differ, so they cannot be compared directly with our results. Cloudflare's origin connection mode is as described in the October 2025 blog post; we did not check its current setting or advertised order.

Among on-path manipulations, we did not perform on-path group reordering. TLS PQ component tampering was rejected by key-format validation, so the combiner binding itself was not tested, and SSH KEX removal ended in a packet format error, so the negotiation defense could not be judged. These three cases are left for future work. The OpenSSH `ssh-order` condition of the cross-implementation negotiation observation ran with the same configuration as the default condition and was effectively a repetition of it.

In both lines, causal isolation added and removed only the `ssl/t1_lib.c` change of the fix commit. Audit visibility was measured on three default output paths at the regular-expression level, and on verbose outputs through `tshark -V` of preserved captures and OpenSSL client `s_client -trace` (9 runs). We did not measure key logs, server-side verbose output, verbose modes of other implementations, or the default outputs of E8–E10. The HRR parser does not reassemble messages spanning multiple TCP segments. The cross-implementation conclusions are limited to the implementations tested and their versions and settings.

## 9. Conclusion

We measured the PQ protection of hybrid key exchange in six implementations, divided into two regions. In on-path manipulation, which the proofs guarantee, all manipulations that reached the binding layer were stopped and the implementations behaved as the proofs predict. The gap lay not in the proofs but in the negotiation function the proofs take as their reference. Even with all five TLS servers configured hybrid-first, the negotiation functions split into three types, and the key-share-first type (OpenSSL single tuple, NSS) gave a classical group to C2, which wanted the hybrid but deferred its key share. The NSS source shows a selection rule that treats X25519 and `X25519MLKEM768` as the same 256-bit strength, which explains this choice. In OpenSSL we reproduced a defect in which the server breaks its own policy (CVE-2026-2673) and confirmed its cause with a single fix change in both the 3.5 and 3.6 lines. The measured default and verbose tool outputs never raised an automatic warning, and for TLS only the verbose outputs showed the advertised and negotiated groups in one place. We found no C2 among 16 default-configured clients (14 libraries and tools, 2 headless browsers). Botan, as C3, received a classical group or, after an HRR, the hybrid depending on the server's selection type, but this is a separate client-preferred classical negotiation. The defect we observed belongs to one library, but the structure in which actual PQ use depends on negotiation functions that differ between implementations and on the client's key-share strategy was observed across the five TLS implementations tested. In the PQ transition, "we turned on the hybrid" and "the hybrid is in use" have to be checked separately.

## References

1. E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018. <https://www.rfc-editor.org/rfc/rfc8446>
2. D. Stebila, S. Fluhrer, S. Gueron, "Hybrid Key Exchange in TLS 1.3", RFC 9954, Informational, July 2026. <https://datatracker.ietf.org/doc/rfc9954/>
3. K. Kwiatkowski, P. Kampanakis, B. E. Westerbaan, D. Stebila, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3", RFC 10024, Proposed Standard, August 2026. <https://datatracker.ietf.org/doc/rfc10024/>
4. OpenSSL, `SSL_CTX_set1_curves(3)` manual page, OpenSSL 3.5. <https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/>
5. OpenSSL Security Advisory [20260313], "OpenSSL TLS 1.3 server may choose unexpected key agreement group" (CVE-2026-2673). <https://openssl-library.org/news/secadv/20260313.txt>
6. CVE Record, CVE-2026-2673. <https://www.cve.org/CVERecord?id=CVE-2026-2673>
7. OpenSSL, commit `85977e013f32ceb96aa034c0e741adddc1a05e34`, "Fix group tuple handling in DEFAULT expansion" (3.5 branch). <https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34>
8. OpenSSL, commit `2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f`, "Fix group tuple handling in DEFAULT expansion" (3.6 branch). <https://github.com/openssl/openssl/commit/2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f>
9. K. Bhargavan, C. Brzuska, C. Fournet, M. Green, M. Kohlweiss, S. Zanella-Béguelin, "Downgrade Resilience in Key-Exchange Protocols", IEEE Symposium on Security and Privacy, 2016.
10. B. Gupta, S. Rana, "Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost", arXiv:2609.21273, 2026.
11. B. Beurdouche et al., "A Messy State of the Union: Taming the Composite State Machines of TLS", IEEE Symposium on Security and Privacy, 2015.
12. D. Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice", ACM Conference on Computer and Communications Security (CCS), 2015.
13. T. Ylonen, C. Lonvick, "The Secure Shell (SSH) Transport Layer Protocol", RFC 4253, January 2006. <https://www.rfc-editor.org/rfc/rfc4253>
14. The Go Authors, `crypto/tls` package documentation, `Config.CurvePreferences`, Go 1.26. <https://pkg.go.dev/crypto/tls#Config>
15. rustls, `CryptoProvider::kx_groups` documentation, rustls 0.23.45. <https://docs.rs/rustls/0.23.45/rustls/crypto/struct.CryptoProvider.html>
16. BoringSSL, commit `7fb4d3da5082225c7180267e9daad291887ce982`, `ssl/extensions.cc` and `ssl/tls13_server.cc`. <https://boringssl.googlesource.com/boringssl/+/7fb4d3da5082225c7180267e9daad291887ce982/ssl/extensions.cc>
17. NSS, tag `NSS_3_120_RTM`, `lib/ssl/tls13con.c` and `lib/ssl/sslsock.c` (GitHub mirror). <https://github.com/nss-dev/nss/blob/NSS_3_120_RTM/lib/ssl/tls13con.c>
18. Caddy, v2.11.4 release and official binary checksums. <https://github.com/caddyserver/caddy/releases/tag/v2.11.4>
19. The Go Authors, "Go, Backwards Compatibility, and GODEBUG" (`tlsmlkem` history and defaults). <https://go.dev/doc/godebug>
20. D. Benjamin, "Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility", RFC 8701, January 2020. <https://www.rfc-editor.org/rfc/rfc8701>
21. D. Benjamin, "TLS Key Share Prediction", draft-ietf-tls-key-share-prediction-04, Internet-Draft (expired 20 September 2026), 19 March 2026. <https://www.ietf.org/archive/id/draft-ietf-tls-key-share-prediction-04.txt>
22. N. Wickramasinghe, F. Li, S. Jha, A. Shaghaghi, "Mind the Gap: Policy vs Reality in Post-Quantum TLS Deployment", arXiv:2607.29005, 31 July 2026. <https://arxiv.org/abs/2607.29005>
23. B. Westerbaan, "State of the post-quantum Internet in 2025", The Cloudflare Blog, 28 October 2025. <https://blog.cloudflare.com/pq-2025/>

## Appendix A. Reproduction information

Raw data (per-run JSON records, packet captures, client, server, capture and proxy logs), build logs and analysis code are preserved in the repository. Detailed evidence on samples, environments and hashes is in `docs/EVIDENCE.md`, and reproduction commands are in `docs/research/REPRODUCTION.md`.

- Data locations (`docs/research/baselines/raw/`): E11 `v1.8/` (24 runs) and the Botan C3 policy control `v1.8-e8/` (15 runs; `v1.8-diagnose/` excluded), E8 `v1.5/` (105 runs), latest-BoringSSL control `v1.5-boringssl-latest/` (9 runs), E9 `v1.6/` (36 runs), default direct connections `v1.6-direct/` (36 runs), v1.6 rerun `v1.6-caddy-2.11.4/` (36 runs, including 9 Caddy 2.11.4 C1–C3 runs), raw Caddy and NSS environment check logs, E10 and `-trace` reruns `v1.7/` (15 runs) with `v1.7-setup.log`, verbose capture re-measurement `v1.7-tshark-verbose-audit.json`, E5 `v1.2/` (60 runs) and `v1.2-s4/` (20 auxiliary runs), E6 `v1.3/` (120 runs) with `v1.3-build.log`, `v1.7-openssl36/` (60 runs) with `v1.7-build36.log` and `v1.7-ldd36.log`, E7 `v1.4/` (60 runs), E1 and E2 `phase-4/` (60 runs), E3, E4 and default negotiation `v1.1/` (90 runs).
- Recomputing results (from `tools/`): `python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8` (E11 defaults), `python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8-e8` (Botan C3 policy control), `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5` (E8), `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5-boringssl-latest` (latest BoringSSL), `python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6` (E9), `--report ../docs/research/baselines/raw/v1.6-direct` (direct connections), `--report ../docs/research/baselines/raw/v1.6-caddy-2.11.4` (v1.6 rerun; includes 9 Caddy 2.11.4 runs), `python -m faultinject.analyze --v12` (E5, `CVE-2026-2673 verdict: reproduced`), `--v13` (E6, `Causal-isolation verdict: consistent`), `--v17` (E6 3.6 variants, `3.6 causal-isolation verdict: consistent`), `python -m faultinject.v17 --report ../docs/research/baselines/raw/v1.7 --verbose-json ../docs/research/baselines/raw/v1.7-tshark-verbose-audit.json` (E10, `-trace`, `tshark -V`), `--v12 --run-dir ../docs/research/baselines/raw/v1.4` (E7, verdict line `reproduced`), `python -m faultinject.analyze` (E1 and E2), `--v11` (E3 and E4; the HRR column of this output is the record at collection time and shows 0 for E3 OpenSSL; the capture-reverified value of 10/10 is in `docs/EVIDENCE.md`). E8 servers are prepared with `tools/v15_setup.sh`, E9 clients and servers with `tools/v16_setup.sh`, and E10 browsers with `tools/v17_setup.sh` (Go and rustls sources are in `tools/v15/`).
- CVE case binaries: `openssl` SHA-256 of the client and the 3.5.5 server `7b1a89948e5e…`, 3.5.6 `88a896e54ede…`, 3.6.1 `d1199e01f04d…`, 3.6.2 `5851a0b61487…`. The two patched variants have the same executable as the originals and differ only in `libssl.so.3` (3.5.5-cherrypick `ef30c6d8de54…`, 3.5.6-revert `a9d8f36e38b2…`; originals 3.5.5 `a785209382…`, 3.5.6 `aff23fc605…`). The `libssl.so.3` of 3.6.1 and 3.6.2 are `fb70fdbf1a67…` and `708d5e708526…`, and the 3.6 variants are 3.6.1-cherrypick `c06395759288…` and 3.6.2-revert `8aea8de16e26…`. We confirmed with `ldd` that each server loads its own `libssl`, and the executables have no RPATH/RUNPATH.
- Sources: 3.5.5 `67b5686b…`, 3.5.6 `286ddeaa…`, 3.6.1 `c9a9e5b1…`, 3.6.2 `fe686e15…`. The variant builds are made with `tools/v13_build_variants.sh`.
- HRR criterion: whether the captured ServerHello random is the RFC 8446 HRR constant `cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`.
- Reproduction packages: the v1.1–v1.7 ZIPs in `dist/` contain each experiment's raw data, documents, tools and tests. The S4 auxiliary sample is only in the repository. `dist/pq-hybrid-downgrade-repro.zip` is the initial (E1, E2) package.

## Appendix B. Research history and corrections

The study began with the proposal's comparison of implementations × fault types (E1, E2). The initial analysis read every E2 rejection as "binding defense succeeded", but re-examining the failure causes showed that the TLS rejections occurred in key-format validation, and we corrected this. We then added on-path removal (E3) and negotiation without an attacker (E4) (v1.1). At first we treated OpenSSL's missing HRR in E4 as a defect candidate, but corrected the interpretation after confirming that the server setting was a single tuple and the behavior was documented. We also used captures to fix E3 HRRs missing from the collected records because OpenSSL logs label an HRR as `ServerHello`, and afterwards switched the HRR criterion to captures. These corrections led to E5 (v1.2) and E6 (v1.3). E7 (v1.4) complemented E5's classical-first client condition, and E8 (v1.5) broadened the evidence for RQ3 to five TLS implementations. E9 (v1.6) was added to check whether E8's PQ omission condition also holds under default settings; it showed that the default clients tested do not meet the condition, and we narrowed the scope of the conclusion. That revision introduced the terminological distinction between attacker-driven "downgrade" and attacker-free "PQ omission". v1.7 addressed three remaining weaknesses: it repeated the 3.6 causal isolation at file level, surveyed the ClientHello of two headless browsers, and extended the audit visibility measurement to verbose outputs. v1.8 extended the real default candidates. We re-examined, against the raw ClientHello order, a derived classification that first read Botan as C2, corrected it to C3, and then added a control across five server types. v1.9 added, without new measurements, three external public sources [21, 22, 23], verified against their originals, as context in related work and the discussion. The extended sample had no C2, and only Botan C3's results varied with the server's selection type.

## Appendix C. Full experiment matrix

| Code | Experiment | Region | Method |
|---|---|---|---|
| E8 | Negotiation-function comparison | B | Configure five TLS server implementations hybrid-first and connect fixed OpenSSL clients C1, C2, C3 |
| E9a | Client default survey | B | Connect six client libraries without group settings to a default OpenSSL 3.5.6 server and record the ClientHello |
| E9b | Real server software | B | Connect C1–C3 to default nginx and Caddy |
| E9c | Default clients × default servers, direct | B | Connect six default clients to default nginx and Caddy 2.6.2 |
| E10 | Browser default survey | B | Record the ClientHello of headless Chrome and Firefox |
| E11 | Extended real defaults and Botan C3 policy control | B | Survey 8 additional default clients and connect Botan C3 to five server selection types |
| E5 | Server-setting defect case | B | Compare OpenSSL S1 single tuple, S2 tuple boundary, S3 `DEFAULT` across 3.5.5 and 3.5.6 |
| E6 | Causal isolation | B | Repeat E5 after applying and removing only the `ssl/t1_lib.c` change of the 3.5 and 3.6 fix commits |
| E7 | Hybrid-first C2 | B | Repeat E5's servers and settings with a C2 client |
| E4 | Client-preferred classical negotiation | B | Connect a client that advertises hybrid and classical groups with the classical group first |
| E1 | Classical-only offer (baseline) | — | The client offers only classical groups or KEX |
| E2 | PQ component tampering | A | A proxy flips bits in only the PQ component of the hybrid public value |
| E3 | Hybrid removal | A | A proxy removes hybrid entries from the ClientHello or SSH KEXINIT |

## Appendix D. AI-to-human responsibility disclosure

AI was used for the experiment tools (fault-injection proxy, control runner, packet capture parser, audit visibility measurement, verdict code), variant build scripts, run automation, raw data aggregation, source code examination, the draft normative analysis, and the drafting of this paper. An independent AI reviewer checked each stage's output against the raw data. The author decided the research questions and the framing of the paper, the reproduction verdict rules, and the scope and priorities of the experiment matrix and the causal isolation. The author also reviewed and confirmed the interpretation corrections, the raw data and hashes, the commit ancestry, and the scope of the conclusions.

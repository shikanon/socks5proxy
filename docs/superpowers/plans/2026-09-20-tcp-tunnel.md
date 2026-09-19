# TCP Tunnel Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the existing QUIC global IPv4 tunnel, add optional TCP+TLS and explicit unencrypted TCP transports, and compare them with random obfuscation on the user's two servers.

**Architecture:** Share the existing TUN, IPv4 validation, DNS, routing, NAT, session, and reconnect logic through a transport connection interface. TCP transports carry length-delimited IP datagrams over one persistent full-duplex stream; TLS is the default for `tcp`, while `tcp-plain` deliberately has no encryption/integrity protection. Both TCP variants use the same nonce/HMAC authentication exchange, enabling a comparison where TLS is the differing transport layer; QUIC retains its existing wire authentication for compatibility.

**Tech Stack:** Go 1.26, standard-library TCP/TLS/HMAC-SHA256, existing quic-go v0.62.0 and wireguard TUN, Linux network namespaces, systemd, Python/curl measurements.

---

## Execution context

- Worktree: `/Users/bytedance/Documents/socks5proxy-tcp-tunnel`, branch `feat/tcp-tunnel`, base `949ff7ee24d2fc91fb0365ddbd43391ddc8d895b`.
- Original workspace and previous diagnostics: `/Users/bytedance/Documents/socks5proxy`; preserve its untracked reports and `.dbg/`.
- User authorized implementation and real comparison of QUIC, TCP+TLS, and reduced-security TCP+random. No extra implementation permission is required.
- The two referenced superpowers execution skills are not installed. Execute the steps directly using the available tools, with the mandatory bits-unit-test-gen workflow for unit tests.
- Local Go is absent. Client host `106.13.216.217` has `/usr/local/go/bin/go` 1.26.0 and can run package and namespace tests in an isolated source directory.
- Server `101.47.18.93`'s old SSH masters are no longer usable. Local RSA/Ed25519 and client-host RSA are rejected. No unrelated SSH process was terminated. Public-path comparison and deployment require restored legitimate SSH access.
- Server TCP 443 belongs to another service. New test listeners must use separate available high ports; production QUIC remains UDP 443.
- Existing server destination route applies BBR to TCP traffic toward `106.13.216.217`; global TCP default remains cubic.
- Current previous measurements: roughly 13.4% server-to-client UDP loss, reverse sample zero; traditional TCP proxy 1 MiB 5–8 s with BBR; QUIC 1 MiB failed at 120 s. Treat these as history, not fresh results for the new backend.

## File responsibilities

| File | Change |
|---|---|
| `internal/tunnel/config.go` | Transport names/defaults/validation; require certificates only for secure transports |
| `cmd/client/main.go`, `cmd/server/main.go` | Expose `-transport quic|tcp|tcp-plain` for tunnel mode |
| `internal/tunnel/transport/connection.go` | Shared control stream, connection, listener interfaces and dispatch; adapt existing QUIC without changing old Dial/Listen helpers |
| `internal/tunnel/transport/tcp.go` | Framed TCP/TLS connection, bounded reads/writes/auth, heartbeat and cancellation |
| `internal/tunnel/protocol/control.go` | Add challenge message type, nonce/proof fields |
| `internal/tunnel/protocol/auth.go` | Random nonce generation and domain-separated proof generation/verification |
| `internal/tunnel/client/client.go` | Transport dispatch, TCP challenge authentication, reuse current TUN relay and restoration |
| `internal/tunnel/server/server.go` | Transport dispatch and TCP challenge authentication; share session/IP/NAT logic |
| `internal/tunnel/server/sessions.go` | Replace concrete QUIC connection with shared interface |
| `internal/tunnel/server/auth.go` | Verify challenge proof using existing stored SHA-256 token digest |
| `*_test.go` beside the files above | Focused transport, authentication, cancellation, framing, configuration and regression cases |
| `scripts/test-tunnel-linux.sh` | Parameterize transport/obfuscation while retaining lossless namespace assertions |
| `docs/tunnel.md`, `README.md` | Supported modes, exact flag semantics, unsafe mode properties, limitations and examples |
| `docs/tcp-tunnel-verification-2026-09-20.md` | Commands, measured samples, failures, deployed state, hashes and rollback |

## Behavioral contract

1. Empty transport means `quic`; existing invocations remain compatible.
2. `tcp` always uses verified TLS 1.3. Never retry as plaintext or bypass certificate checks.
3. `tcp-plain` is explicit, logs a concise warning, and never sends the token or its stored digest as a credential on the wire. Packet confidentiality/integrity remain absent, even with `random`.
4. Both TCP transports authenticate identically: server fresh 32-byte challenge → client fresh 32-byte nonce and HMAC proof → server signed auth response. SHA-256(token) is the shared proof key; use HMAC domain separation and bind client ID, obfuscation mode and response network parameters.
5. TCP obfuscation uses hex(SHA-256(token)) on both peers. QUIC keeps its existing token-derived obfuscation and control exchange.
6. TCP data uses a 2-byte big-endian payload length followed by the existing encoded IPv4 datagram. Length zero is a heartbeat, never delivered as an IP packet. Maximum encoded payload is 1402 bytes; malformed or truncated frames end the connection.
7. Framing must tolerate arbitrary stream segmentation/coalescing and short writes. Serialize heartbeat/data writes.
8. Limit authentication including control reads/writes to 10 s; application context cancellation closes outstanding TCP I/O. Start data heartbeats only after the control exchange completes. Use 15 s heartbeats, 45 s receive-idle deadline, bounded writes, and keepalive.
9. Keep MTU 1150 by default for all comparisons. QUIC retains its existing MTU cap; TCP can accept the existing supported 576–1400 MTU range.
10. Retain IPv4 source/destination validation, bounded per-session queues, session replacement, fail-closed reconnect behavior and exact network restoration.
11. The backend carries IP packets; SOCKS5+random remains a separate traditional-proxy comparison, not a substitute for UDP/ICMP global capture.

## Task 1: Complete the unit-test preparation gates

- [x] Run bits-unit-test-gen Step1:

```sh
AGENT_SOURCE=trae MODEL_SOURCE=gpt-6 \
SKILL_ROOT=/Users/bytedance/.trae-cn/builtin_skills/bits-unit-test-gen \
bash /Users/bytedance/.trae-cn/builtin_skills/bits-unit-test-gen/scripts/prepare_test.sh \
  --repo-path /Users/bytedance/Documents/socks5proxy-tcp-tunnel
```

Result: `TMP_ROOT=/var/folders/7c/q9tcww7s35g_gbhmm016nvgh0000gn/T/tmp.73AW34nOBC`; `EXEC_SOURCE=""`; utree available at `/Users/bytedance/.local/bin/utree`.

- [x] Read default-context, general-context and Go language prompt; language is Go, existing package tests use the standard testing library and temporary certificates. No new mock dependency.
- [x] Complete Step3 scope extraction and Step4 defect analysis per their reference files. Publish concrete TARGETS and BUG_MAP before generating test cases; missing new features are not automatically pre-existing bugs.
- [x] Read Step5 loop instructions before any test generation; follow package order: protocol, transport, config, server, client.

## Task 2: Add configuration and transport boundaries

**Completed:** configuration, CLI, shared transport boundary and regression tests passed.

- [x] Add and validate transport values. The normalization contract is:

```go
func NormalizeTransport(value string) (string, error) {
    value = strings.ToLower(strings.TrimSpace(value))
    if value == "" {
        value = "quic"
    }
    switch value {
    case "quic", "tcp", "tcp-plain":
        return value, nil
    default:
        return "", fmt.Errorf("unsupported tunnel transport %q", value)
    }
}
```

Add `Transport string` to both configs and assign normalized values in defaults (retain invalid values for Validate to reject where SetDefaults has no error return). Validation must use the normalized value when deciding whether server certificate/key are required.

- [x] Add the same flag on each CLI and pass its value into the tunnel config:

```go
transportMode := flag.String("transport", "quic", "Tunnel transport: quic, tcp (TLS), or tcp-plain (unencrypted)")
```

- [x] Introduce the shared API below. Retain old QUIC `Dial`, `Listen`, `ClientTLS`, `ServerTLS`, and `QUICConfig` for compatibility and existing tests.

```go
type ControlStream interface {
    io.ReadWriteCloser
    SetDeadline(time.Time) error
}

type Conn interface {
    Context() context.Context
    OpenControl(context.Context) (ControlStream, error)
    AcceptControl(context.Context) (ControlStream, error)
    SendDatagram([]byte) error
    ReceiveDatagram(context.Context) ([]byte, error)
    CloseWithError(quic.ApplicationErrorCode, string) error
}

type Listener interface {
    Accept(context.Context) (Conn, error)
    Close() error
    Addr() net.Addr
}
```

Dispatch functions are `DialTunnel(ctx context.Context, addr string, tlsConfig *tls.Config, kind string) (Conn, error)` and `ListenTunnel(addr string, tlsConfig *tls.Config, kind string) (Listener, error)`. QUIC adapters embed their existing concrete objects and provide OpenControl/AcceptControl wrappers. QUIC DATAGRAM support must still be required at both ends. Unknown kinds fail explicitly.

- [x] In unit-test Step5, verify normalization, default QUIC, unknown transport rejection, and certificate requirements for each server mode. Keep existing config tests.

## Task 3: Implement TCP framing and lifetime

**Completed:** framing, TLS validation, deadlines, heartbeats, cancellation, concurrency and state-transition tests passed.

- [x] Build a TCP connection wrapper with one context/cancel cause, one write mutex, one close-once and one start-data-once. The control stream delegates reads/writes/deadlines, but its `Close` transitions to packet mode instead of closing the network connection.
- [x] TCP+TLS client must complete certificate/ALPN verification before returning from DialTunnel. Server TLS handshake happens in the per-connection handler/control acceptance, never serially inside listener Accept.
- [x] Use this write algorithm for each length-prefixed packet, under the connection write mutex:

```go
func writeFrame(w io.Writer, payload []byte) error {
    if len(payload) > 1402 {
        return errors.New("TCP tunnel packet exceeds 1402 bytes")
    }
    frame := make([]byte, 2+len(payload))
    binary.BigEndian.PutUint16(frame, uint16(len(payload)))
    copy(frame[2:], payload)
    for len(frame) > 0 {
        n, err := w.Write(frame)
        if err != nil {
            return err
        }
        if n <= 0 || n > len(frame) {
            return io.ErrShortWrite
        }
        frame = frame[n:]
    }
    return nil
}
```

- [x] Receive with `io.ReadFull` for the 2-byte length and body; reject length >1402 before allocating. Consume zero-length heartbeat frames internally and update the read deadline. EOF/truncation/deadline errors close the connection and cancel its Context.
- [x] Use context cancellation callbacks and network Close to interrupt blocked reads/writes, including server shutdown and authentication. Stop callbacks/goroutines on closure; do not wait for peer activity to cancel.
- [x] Generate focused Step5 transport tests for partial headers, coalesced frames, short/zero writers, oversized frames, truncated payload, heartbeat filtering, cancel blocked read, concurrent data/heartbeat writes, rejected cert/name/ALPN, and logical control close preserving data transport.
- [x] Run relevant transport tests first, then the package including unchanged QUIC tests; use race testing after normal tests converge.

## Task 4: Authenticate TCP without exposing the token

**Completed:** nonce/HMAC exchange, tamper/replay checks and credential-free wire assertions passed.

- [x] Extend Message with `Nonce string` and `Proof string`, both omitempty, and allow `TypeAuthChallenge = "auth_challenge"` in ReadMessage.
- [x] Implement nonce and HMAC helpers in protocol/auth.go. Nonces must decode to exactly 32 bytes.

```go
func NewNonce() (string, error) {
    var nonce [32]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        return "", err
    }
    return hex.EncodeToString(nonce[:]), nil
}

func AuthProof(key [sha256.Size]byte, role, challenge, nonce string, msg Message) string {
    msg.Proof = ""
    msg.Token = ""
    payload, _ := json.Marshal(struct {
        Role string
        Challenge string
        Nonce string
        Message Message
    }{role, challenge, nonce, msg})
    mac := hmac.New(sha256.New, key[:])
    _, _ = mac.Write(payload)
    return hex.EncodeToString(mac.Sum(nil))
}
```

Verification decodes the supplied proof and uses `hmac.Equal`, never normal string comparison. Role labels must differ for request and response. Store only the existing SHA-256(token) digest; do not persist plaintext credentials on the server.

- [x] Both TCP variants use the three-message challenge exchange. Reject unknown clients, non-empty request Token, invalid nonce/proof, unsupported obfuscation, wrong message type/version and invalid response proof.
- [x] Bind response proof to session ID, client/server IP, DNS, MTU and obfuscation before applying any local network changes. QUIC remains on its existing exchange.
- [x] Generate Step5 auth tests for valid exchange, wrong token, replay against a fresh challenge, changed nonce/client/obfs, swapped client/server proof roles and changed response IP/DNS/MTU. Verify encoded TCP auth messages contain neither token nor digest.

## Task 5: Share TUN relay across transports

**Completed:** common relay and session lifecycle passed tests/vet/race and all platform builds. Two historical QUIC auth cancellation issues reproduced three times each on the baseline and passed after repair. Additionally reused Native.ReadPacket batch workspaces; five new cases verify ownership, reuse, batch fallback and read errors.

- [x] Replace client/server/session concrete QUIC connection fields with `transport.Conn`; call OpenControl/AcceptControl and DialTunnel/ListenTunnel.
- [x] Apply a bounded control deadline and ensure parent cancellation interrupts authentication I/O for both transports.
- [x] Build TLS configuration only for `quic` and `tcp`. Log an explicit unencrypted-transport message for `tcp-plain`; never silently downgrade.
- [x] Keep existing datagram codec, source checks, session pool, queue sizes, statistics and restore behavior. Preserve special nonfatal handling of QUIC DatagramTooLargeError.
- [x] Restrict the server's existing MTU cap to QUIC. Include transport in listener and client connection logs without credentials.
- [x] Make relay shutdown join its outgoing/incoming workers before a new connection starts consuming the shared outbound channel. Closing the transport must unblock either worker; avoid leaked readers or concurrent old/new consumers during reconnect.
- [x] Generate focused client/server Step5 handshake/replacement/reconnect tests with interface fakes or local sockets, following existing test style.
- [x] Run all package tests, then vet, then race tests. Compile Linux, macOS and Windows clients without changing dependencies.

## Task 6: Namespace regression and unit-test reporting

**Implementation and unit report completed:** 17 new top-level tests, 80 leaf scenarios passed; coverage skipped per skill gate because no configured requirement; utree flush succeeded. Final namespace results are recorded in the verification report.

- [x] Parameterize the existing namespace script:

```sh
transport_mode="${TUNNEL_TRANSPORT:-quic}"
obfs_mode="${TUNNEL_OBFS:-random}"
```

Pass `-transport "$transport_mode"` to both binaries, and replace the client's fixed obfuscation argument with `-obfs "$obfs_mode"`. Retain outer MTU 1228, 1 MiB hash check, full-MTU ping, UDP fragmentation, fail-closed server stop, firewall cleanup and client route restoration. Authentication uses the existing temporary per-run token file.

- [x] Run transport matrix, sequentially:

```sh
for transport_mode in quic tcp tcp-plain; do
  for obfs_mode in none simple random; do
    TUNNEL_TRANSPORT="$transport_mode" TUNNEL_OBFS="$obfs_mode" \
      bash scripts/test-tunnel-linux.sh
  done
done
```

- [x] Complete bits-unit-test-gen Step6 coverage gate, keeping profiles outside tracked source. Complete Step7 report and `utree flush`.
- [x] Commit only relevant source/tests/docs in the feature worktree after checks pass; no credentials, raw runtime logs or generated binaries.

## Task 7: Real-host comparison and final deployment

**Partially blocked by server SSH:** completed single-host namespace comparisons as an explicitly labeled fallback, not a substitute for the public path. Production server binaries/configuration were not changed. Public-path tests and deployment remain unchecked below.

- [ ] Establish bounded, reliable SSH to both hosts. Use an isolated build directory; do not overwrite `/opt/socks5proxy-release` until verified.
- [ ] Create separate temporary credentials for all benchmark transports. Never reuse the production token in the plaintext experiment. Bind separate server listeners/TUNs/subnets/state dirs, retaining production QUIC and unrelated TCP 443 service.
- [ ] Run identical application traffic with `-obfs random`, MTU 1150 and the already verified peer BBR route. Use a fixed incompressible deterministic payload and SHA-256 check; log connection setup separately from transfer timing.
- [ ] Interleave repeated TCP+TLS and TCP-plain samples instead of comparing a single run. Measure at least three complete 1 MiB samples per TCP mode and bounded larger transfer/upload cases, plus comparable QUIC and legacy SOCKS5+random baselines.
- [ ] Keep budgets and URLs consistent, record full bytes/exit codes/TLS status, CPU where available, and all failures. Do not equate HTTP 200 or partial bodies with success, nor compare compressed and uncompressed pages.
- [ ] Test UDP/TCP DNS, ICMP, small and fragmented UDP, Google/YouTube HTTPS, reconnect, server interruption and exact stop-time network restoration on the new global TCP backends.
- [ ] Choose no insecure default based on an assumed speed gain. If TLS overhead is not reproducibly material, recommend TCP+TLS; expose plaintext as the explicit opt-in tested capability.
- [ ] Deploy verified binaries with rollback copies as appropriate, preserve QUIC support/configuration, stop temporary listeners, remove temporary secrets, and leave client stopped with its original network restored.
- [ ] Write the verification report with raw sample locations, security/performance tradeoff, remaining path-loss limitations and exact rollback steps. Integrate the tested feature into the user's workspace without overwriting unrelated diagnostic files.

## Self-review

- QUIC retained and defaults compatible; both secure and explicit insecure TCP covered.
- Full IPv4 capture preserved; legacy SOCKS5 is a baseline, not a replacement.
- No silent downgrade or production-token exposure in plaintext tests.
- Packet framing, cancellation, heartbeat, reconnect and malformed input included.
- TLS/unencrypted throughput claims require repeated same-condition runtime evidence.
- Unit workflow gates and final report/cleanup included; no permission stop added to already authorized work.

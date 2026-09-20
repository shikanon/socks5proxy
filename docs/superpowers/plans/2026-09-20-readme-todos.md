# README Reliability and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the four unchecked README items with verified proxy resource cleanup, accurate security guidance, same-host examples, and current download/troubleshooting instructions.

**Architecture:** Keep the existing byte-obfuscation wire protocol and public Client/Server wrappers. Add context-aware proxy entry points and shared bounded connection serving, timeout-aware dialing, and half-close-aware TCP relay. Parse SOCKS frames exactly and use Go's HTTP parser for HTTP forwarding and CONNECT.

**Tech Stack:** Go 1.26, standard net/http/net/context packages, existing Go tests, Python black-box resource/load checks, GitHub Actions.

Execution takes place in `fix/readme-todos` at `/Users/bytedance/Documents/socks5proxy-readme-todos`. The referenced superpowers execution skills are unavailable; execute directly under the user's development authorization.

## Evidence and issue mapping

| README item | Evidence | Resolution |
| --- | --- | --- |
| #29 security model | Checkbox format already standard; proxy and tunnel trust boundaries are not explained; legacy CLI documentation incorrectly promises password default 123456 | Add `docs/security.md`, concise README model and truthful defaults |
| #2 same-machine deployment | Issue confirms wrong `-recv`/browser protocol caused errors | Give two loopback ports and matching HTTP/SOCKS curl/browser examples; distinguish proxy from global TUN |
| #3 too many open files | `client.go` registers local Close after upstream Dial; both relay directions wait indefinitely; unbounded accepts; no handshake/dial/idle deadline; Accept errors spin | Deterministic cleanup, bounded sessions, deadline/cancellation, accept backoff; descriptor recovery checks |
| #4 download instructions | Issue closed in 2026 after migration to Releases, but README still unchecked and usage stale | Link actual release listing, architecture selection, checksum commands and build fallback; add troubleshooting |

Other confirmed code facts: HTTP mode only reads the first 1024 bytes and indexes unvalidated request tokens; SOCKS handshake uses one TCP Read and assumes message boundaries; NMETHODS arithmetic uses uint8 and overflows for 254/255; method selection accepts unavailable no-auth; server sends CONNECT success before destination dial completes.

## Task 1: Resource and lifecycle layer

Files: `proxy_runtime.go` (new), `client.go`, `server.go`, `cmd/client/main.go`, `cmd/server/main.go`.

- [x] Add the public API while retaining current entry points:

```go
type ProxyOptions struct {
    MaxConnections int
    DialTimeout time.Duration
    HandshakeTimeout time.Duration
    IdleTimeout time.Duration
}
func ClientContext(ctx context.Context, local, remote, obfs, password, mode string, options ProxyOptions) error
func ServerContext(ctx context.Context, local, obfs, password string, options ProxyOptions) error
```

- [x] Defaults: 256 simultaneous sessions per process, 10s dial, 10s handshake, 5min no traffic in either direction. Zero selects defaults, negative values are invalid. Admission acquires a slot before Accept; context cancellation closes listener and all active sockets and waits for workers.
- [x] Use `net.Dialer.DialContext` with deadlines. Register inbound connection cleanup before any dial. Retry temporary resource-related accept errors with capped exponential backoff; closed/permanent listener errors return.
- [x] Relay normal EOF with destination `CloseWrite` so pending responses can drain; errors close both sockets; all workers end on cancellation or no-traffic timeout. Successful traffic in either direction refreshes both endpoints' idle deadlines.
- [x] Expose `-max-connections`, `-dial-timeout`, `-handshake-timeout`, `-idle-timeout` in proxy mode and signal.NotifyContext shutdown. Bind local client to `127.0.0.1:8888` by default. Reject invalid `-recv` before listening.

## Task 2: SOCKS and HTTP framing

Files: `server.go`, `socks5.go`, `client.go`, `http_proxy.go` (new).

- [x] Read exactly two SOCKS greeting bytes, then the advertised method bytes (up to 255); leave pipelined request bytes unread. Use int arithmetic and require the client to offer method 0; reply 0xff and close otherwise.
- [x] Read exact request header/address/port. Preserve the exported `LSTRequest` compatibility method, but let the production path defer domain resolution to context-aware dialing. Reply success only after target connection succeeds; failed target dial returns SOCKS failure.
- [x] Parse HTTP requests with `http.ReadRequest` on a buffered reader with a bounded header section. Validate method, target, port and URI; return bounded 400/431/502 responses instead of panicking.
- [x] HTTP CONNECT establishes the SOCKS destination before acknowledging 200, then relays all buffered bytes and half-closes. Ordinary HTTP forwards the entire request/body with proxy-only headers removed and closes the local connection after the response; no fixed 1KB first-packet assumption.

## Task 3: Tests and reproduction

Files: `proxy_runtime_test.go`, `proxy_reliability_test.go`, relevant existing `server_test.go` / `e2e_test.go`, `scripts/test-proxy-resources.py`.

- [x] Complete bits-unit-test-gen Step1–4 and output concrete target/defect mapping before generating tests. Primary package is repository root; no external mocks required.
- [x] Exercise upstream refusal closing local socket, slow handshake expiry, session admission limits, stop while blocked in accept/read, half-close draining, relay I/O error cleanup and idle timeout.
- [x] Exercise fragmented/pipelined SOCKS handshake and max methods; failed dial must never acknowledge success.
- [x] Exercise same-host SOCKS and HTTP modes, HTTPS CONNECT, large/fragmented HTTP POST and malformed input. Replace fixed-port/sleep fixtures where necessary with context-owned listeners and cleanup.
- [x] Add a black-box Linux resource check using real client/server binaries, `/proc/<pid>/fd`, low RLIMIT_NOFILE and repeated failed dials/short connections. Record before/after descriptor counts and limits without changing system-wide settings.
- [x] Run `go test -race -timeout 90s ./...`, `go vet ./...`, staticcheck and desktop cross-builds. Run smoke/resource script; document observed limits and reproducible commands.

## Task 4: Docs and integration

Files: `README.md`, `docs/security.md`, `docs/proxy.md`, `docs/troubleshooting.md`, `docs/release.md`, `docs/verification-readme-todos-2026-09-20.md`.

- [x] Security model covers passive/active attacker, weak obfuscation key space (at most 256 substitution tables), local unauthenticated listener, server/exit trust, no destination ACL, TLS protection limits, plaintext opt-in and IPv4/kill-switch limitations.
- [x] Same-host examples use server 127.0.0.1:18888, client 127.0.0.1:8888, explicit matching password/type, `curl --noproxy "" --proxy ...` and browser protocol settings. Warn against pointing proxy destination back to either listener.
- [x] Download instructions include GitHub Releases listing, platform/architecture, `chmod +x`, Wintun ZIP and individual artifact checksum verification; source fallback when a new target has not been released.
- [x] Troubleshooting maps EMFILE, connection refused, protocol mismatch, idle expiry, DNS/TLS/TUN failures to exact checks. Budget approximately two sockets per session plus process overhead and advise matching MaxConnections to RLIMIT_NOFILE.
- [x] Check all README items only after each criterion is implemented/verified. Do not close or comment on GitHub issues without separate messaging authorization.
- [x] Commit and fast-forward original master, preserve existing untracked diagnostics. No remote push or public release implied by this request.

Implementation and verification evidence: [README TODO verification](../../verification-readme-todos-2026-09-20.md). The initial regression tests reproduced five defect classes; all now pass. Linux low-FD checks retain a seven-descriptor baseline after failed dials and 400 successful short sessions. macOS/Linux race tests, vet, staticcheck and ten desktop cross-builds pass.

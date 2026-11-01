package socks5proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

func validateLoopbackAddress(address string, allowZero bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || number < 0 || number > 65535 || (!allowZero && number == 0) {
		return errors.New("expected a loopback IP and port, e.g. 127.0.0.1:8090")
	}
	return nil
}

func proxyPAC(address, mode string, options ProxyOptions) string {
	directive := "PROXY " + address
	if mode == "socks5" {
		directive = "SOCKS5 " + address
	}
	encodedDirective, _ := json.Marshal(directive)
	patterns := options.Rules.Patterns()
	if options.Scope == "all" {
		patterns = []string{"*"}
	}
	encodedPatterns, _ := json.Marshal(patterns)
	// Use the same bounded glob algorithm as routing.Rules, with no DNS calls.
	// Browsers supply ASCII/punycode hosts. JSON encoding prevents rule injection.
	return fmt.Sprintf(`// socks5proxy: website host routing; reload PAC after changing rules.
var proxyPatterns = %s;
function proxyGlob(pattern, host) {
  var p = 0, h = 0, star = -1, retry = 0;
  while (h < host.length) {
    if (p < pattern.length && (pattern.charAt(p) === "?" || pattern.charAt(p) === host.charAt(h))) { p++; h++; }
    else if (p < pattern.length && pattern.charAt(p) === "*") { star = p++; retry = h; }
    else if (star >= 0) { p = star + 1; h = ++retry; }
    else { return false; }
  }
  while (p < pattern.length && pattern.charAt(p) === "*") { p++; }
  return p === pattern.length;
}
function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  for (var i = 0; i < proxyPatterns.length; i++) {
    var pattern = proxyPatterns[i];
    if (proxyGlob(pattern, host) || (pattern.slice(0, 2) === "*." && proxyGlob(pattern.slice(2), host))) {
      return %s;
    }
  }
  return "DIRECT";
}
`, encodedPatterns, encodedDirective)
}

func pacHandler(content string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy.pac" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(content))
		}
	})
}

func serveClientProxy(ctx context.Context, listener net.Listener, remote string, auth socks5Auth, mode string, options ProxyOptions) error {
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var pac *http.Server
	var pacDone chan error
	if options.PACListen != "" {
		address := listener.Addr().String()
		if err := validateLoopbackAddress(address, false); err != nil {
			return fmt.Errorf("PAC requires a loopback proxy listener: %w", err)
		}
		pacListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", options.PACListen)
		if err != nil {
			return err
		}
		pac = &http.Server{
			Handler:           pacHandler(proxyPAC(address, mode, options)),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    maxProxyHeader,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		pacDone = make(chan error, 1)
		stop := context.AfterFunc(ctx, func() { pac.Close() })
		defer stop()
		go func() {
			err := pac.Serve(pacListener)
			cancel()
			pacDone <- err
		}()
		log.Printf("PAC URL: http://%s/proxy.pac", pacListener.Addr())
	}
	err := serveProxy(ctx, listener, options, func(ctx context.Context, conn net.Conn) error {
		return handleProxySession(ctx, conn, remote, auth, mode, options)
	})
	if pac != nil {
		pac.Close()
		if pacErr := <-pacDone; pacErr != nil && !errors.Is(pacErr, http.ErrServerClosed) && err == nil {
			err = pacErr
		}
	}
	return err
}

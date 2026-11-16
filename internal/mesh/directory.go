package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Lease struct {
	Member
	Expires time.Time `json:"expires"`
}
type Directory struct {
	mu        sync.Mutex
	inventory map[string]Member
	leases    map[string]Lease
	now       func() time.Time
}

func NewDirectory(members []Member) *Directory {
	d := &Directory{inventory: map[string]Member{}, leases: map[string]Lease{}, now: time.Now}
	for _, m := range members {
		m.Endpoints = append([]string(nil), m.Endpoints...)
		m.Ports = append([]uint16(nil), m.Ports...)
		d.inventory[m.ID] = m
	}
	return d
}
func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func (d *Directory) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "authentication required", 401)
			return
		}
		id, e := identity(*r.TLS)
		if e != nil {
			http.Error(w, "authentication required", 401)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		member, ok := d.inventory[id]
		if !ok {
			http.Error(w, "member not authorized", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.URL.Path == "/v1/register" && r.Method == http.MethodPost:
			var request struct {
				Endpoint string `json:"endpoint"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !contains(member.Endpoints, request.Endpoint) {
				http.Error(w, "invalid candidate", 400)
				return
			}
			registered := member
			registered.Endpoints = []string{request.Endpoint}
			lease := Lease{registered, d.now().Add(leaseTime)}
			d.leases[id] = lease
			_ = json.NewEncoder(w).Encode(lease)
		case r.URL.Path == "/v1/peers" && r.Method == http.MethodGet:
			now := d.now()
			rows := []Lease{}
			for id, l := range d.leases {
				if l.Expires.After(now) {
					rows = append(rows, l)
				} else {
					delete(d.leases, id)
				}
			}
			_ = json.NewEncoder(w).Encode(rows)
		default:
			http.Error(w, "not found", 404)
		}
	})
}
func controlClient(c Config) (*http.Client, error) {
	u, e := url.Parse(c.ControlURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("control URL must be a credential-free HTTPS origin")
	}
	cfg, e := TLS(c, false)
	if e != nil {
		return nil, e
	}
	cfg.NextProtos = []string{"http/1.1"}
	cfg.ServerName = c.ControlName
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control redirect forbidden") }}, nil
}
func requestControl(ctx context.Context, c Config, path, method string, data []byte, out any) error {
	client, e := controlClient(c)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	r, e := http.NewRequestWithContext(ctx, method, c.ControlURL+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	res, e := client.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("mesh control request rejected")
	}
	payload, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(payload) > 65536 {
		return errors.New("invalid control response size")
	}
	return json.Unmarshal(payload, out)
}
func Register(ctx context.Context, c Config) error {
	body, _ := json.Marshal(map[string]string{"endpoint": c.Endpoint})
	var lease Lease
	return requestControl(ctx, c, "/v1/register", http.MethodPost, body, &lease)
}
func Peers(ctx context.Context, c Config) ([]Lease, error) {
	var out []Lease
	e := requestControl(ctx, c, "/v1/peers", http.MethodGet, nil, &out)
	return out, e
}
func ControlTLS(c Config) (*tls.Config, error) {
	cfg, err := TLS(c, true)
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = []string{"http/1.1"}
	return cfg, nil
}

package mesh

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteExamples prepares non-secret configuration files. It never generates or copies private keys.
func WriteExamples(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	members := []Member{{ID: "client", IP: "100.64.0.1", Endpoints: []string{"192.0.2.10:18444"}}, {ID: "server", IP: "100.64.0.2", Endpoints: []string{"198.51.100.20:18444"}, Ports: []uint16{8080}}, {ID: "control", IP: "100.64.0.3"}}
	for i, id := range []string{"client", "server", "control"} {
		c := Config{Version: 1, ID: id, IP: fmt.Sprintf("100.64.0.%d", i+1), Cert: "private/" + id + ".crt", Key: "private/" + id + ".key", CA: "private/ca.crt", Listen: "0.0.0.0:18444", Members: members, ControlURL: "https://203.0.113.30:18443", ControlName: "control"}
		if id != "control" {
			c.Endpoint = members[i].Endpoints[0]
		}
		if id == "server" {
			c.Services = []Service{{Port: 8080, Target: "127.0.0.1:28888", Allow: []string{"client"}}}
		}
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		p := filepath.Join(dir, id+".example.json")
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, err = f.Write(append(data, '\n'))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

package network

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

type Command struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

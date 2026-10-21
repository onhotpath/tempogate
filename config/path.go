package config

import (
	"os"
	"strings"
)

// EnvPath names the environment variable that selects a config file when
// --config is not given.
const EnvPath = "TEMPOGATE_CONFIG"

// Path is an fx-injected optional config-file path. Empty means: use
// ./application.yaml if present.
type Path string

// ProcessPath returns the config file this process was asked to load: the
// --config flag, else $TEMPOGATE_CONFIG, else empty.
//
// Configuration is loaded while the fx graph is built, before cobra parses
// the command line (the logger, and so every subcommand, depends on it), so
// the flag is read from os.Args directly. The root command still declares
// --config so cobra accepts it on every subcommand.
func ProcessPath() Path {
	return processPath(os.Args[1:])
}

func processPath(args []string) Path {
	if p := PathFromArgs(args); p != "" {
		return p
	}
	return Path(os.Getenv(EnvPath))
}

// PathFromArgs finds --config in args the way cobra would parse it: as
// "--config <path>" or "--config=<path>", anywhere before a "--" terminator,
// the last occurrence winning.
func PathFromArgs(args []string) Path {
	var p Path
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return p
		case a == "--config":
			if i+1 < len(args) {
				i++
				p = Path(args[i])
			}
		case strings.HasPrefix(a, "--config="):
			p = Path(strings.TrimPrefix(a, "--config="))
		}
	}
	return p
}

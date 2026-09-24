package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/onhotpath/ferry"
	"github.com/onhotpath/ferry/driver/env"
	"github.com/onhotpath/ferry/driver/yaml"
	"go.uber.org/fx"
)

// Path is an fx-injected optional config-file path. Empty means: search the
// default locations (cwd and three parents) and use whichever yaml is found.
type Path string

type Params struct {
	fx.In

	Path Path `optional:"true"`
}

// New is the fx constructor: applies defaults, layers in yaml + env, and
// returns the resolved *Config. Errors fail fx graph construction.
func New(p Params) (*Config, error) {
	c := defaultConfig()
	if _, err := Load(c, string(p.Path)); err != nil {
		return nil, err
	}
	return c, nil
}

// Load merges defaults (already in `into`) with values from a yaml file (if
// found at `filePath` or under default search paths) and OS env vars. OS env
// wins over yaml. Returns the resolved yaml path actually used (empty if none).
//
// Env keys use Ferry's default underscore separator, e.g. LOG_LEVEL.
func Load(into *Config, filePath string) (string, error) {
	path, err := configPath(filePath)
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	if path != "" {
		*into, err = ferry.LoadOver(ctx, *into, yaml.NewSource(path))
		if err != nil {
			return "", fmt.Errorf("load config %q: %w", path, err)
		}
	}
	*into, err = ferry.LoadOver(ctx, *into, env.New())
	if err != nil {
		return "", fmt.Errorf("load environment: %w", err)
	}
	return path, nil
}

func configPath(explicit string) (string, error) {
	if explicit != "" {
		info, err := os.Stat(explicit)
		if err != nil {
			return "", fmt.Errorf("config file %q: %w", explicit, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("config file %q is a directory", explicit)
		}
		return explicit, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for range 4 {
		path := filepath.Join(dir, "application.yaml")
		_, err := os.Stat(path)
		if err == nil {
			return path, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("config file %q: %w", path, err)
		}
		dir = filepath.Dir(dir)
	}
	return "", nil
}

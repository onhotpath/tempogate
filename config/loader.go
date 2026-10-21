package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/onhotpath/ferry"
	"github.com/onhotpath/ferry/driver/env"
	"github.com/onhotpath/ferry/driver/yaml"
	"go.uber.org/fx"
)

// implicitFile is the config file looked up in the working directory when no
// explicit path is given. Parent directories are deliberately not searched: on
// a shared host a file planted above the cwd could otherwise repoint the
// upstream IdP endpoints.
const implicitFile = "application.yaml"

type Params struct {
	fx.In

	Path Path `optional:"true"`
}

// Source reports which yaml file Load merged, if any.
type Source struct {
	// Path is the yaml file merged; empty when none was.
	Path string

	// Skipped is why the implicit ./application.yaml could not be read. The
	// implicit lookup is a convenience, so an unreadable working directory
	// (the image's /home/nonroot under an arbitrary uid) must not stop the
	// process; an explicit path that cannot be read is an error instead.
	Skipped error
}

// Loaded is what New provides: the configuration and where it came from.
type Loaded struct {
	fx.Out

	Config *Config
	Source Source
}

// New is the fx constructor: applies defaults, layers in yaml + env, and
// returns the resolved *Config. Errors fail fx graph construction.
func New(p Params) (Loaded, error) {
	c := defaultConfig()
	src, err := Load(c, string(p.Path))
	if err != nil {
		return Loaded{}, err
	}
	return Loaded{Config: c, Source: src}, nil
}

type logSourceParams struct {
	fx.In

	Source Source
	// Logger is optional so config.Fx() also builds in graphs that only need
	// the projected values (package tests); the app always provides one.
	Logger *slog.Logger `optional:"true"`
}

// logSource reports the yaml file in use once the logger, which itself needs
// the loaded log level, exists.
func logSource(p logSourceParams) {
	if p.Logger == nil {
		return
	}
	switch {
	case p.Source.Skipped != nil:
		p.Logger.Warn("skipping unreadable config file", "path", implicitFile, "error", p.Source.Skipped)
	case p.Source.Path != "":
		p.Logger.Debug("loaded config file", "path", p.Source.Path)
	}
}

// Load merges defaults (already in `into`) with values from a yaml file (the
// explicit `filePath`, else ./application.yaml if present) and OS env vars.
// OS env wins over yaml.
//
// Env keys use Ferry's default underscore separator, e.g. LOG_LEVEL.
func Load(into *Config, filePath string) (Source, error) {
	src, err := configSource(filePath)
	if err != nil {
		return Source{}, err
	}
	ctx := context.Background()
	if src.Path != "" {
		*into, err = ferry.LoadOver(ctx, *into, yaml.NewSource(src.Path))
		if err != nil {
			return Source{}, fmt.Errorf("load config %q: %w", src.Path, err)
		}
	}
	*into, err = ferry.LoadOver(ctx, *into, env.New())
	if err != nil {
		return Source{}, fmt.Errorf("load environment: %w", err)
	}
	return src, nil
}

func configSource(explicit string) (Source, error) {
	if explicit != "" {
		info, err := os.Stat(explicit)
		if err != nil {
			return Source{}, fmt.Errorf("config file %q: %w", explicit, err)
		}
		if info.IsDir() {
			return Source{}, fmt.Errorf("config file %q is a directory", explicit)
		}
		return Source{Path: explicit}, nil
	}
	// Open rather than Stat so a file that exists but cannot be read is
	// skipped here instead of failing later inside the yaml source.
	f, err := os.Open(implicitFile)
	switch {
	case err == nil:
		_ = f.Close()
		return Source{Path: implicitFile}, nil
	case errors.Is(err, fs.ErrNotExist):
		return Source{}, nil
	case errors.Is(err, fs.ErrPermission):
		return Source{Skipped: err}, nil
	default:
		return Source{}, fmt.Errorf("config file %q: %w", implicitFile, err)
	}
}

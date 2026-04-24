package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
)

type logLevelValue struct {
	slogLevel    slog.Level
	zerologLevel zerolog.Level
}

func (l *logLevelValue) Set(s string) error {
	var err error
	if strings.ToUpper(s) == "TRACE" {
		l.slogLevel = slog.LevelDebug
	} else {
		err = l.slogLevel.UnmarshalText([]byte(s))
		if err != nil {
			return err
		}
	}
	l.zerologLevel, err = zerolog.ParseLevel(s)
	return err
}

func (l *logLevelValue) String() string {
	return l.zerologLevel.String()
}

type logFormatValue struct {
	format string
}

func (l *logFormatValue) Set(s string) error {
	if s != "text" && s != "json" {
		return fmt.Errorf("invalid log format: %s", s)
	}
	l.format = s
	return nil
}

func (l *logFormatValue) String() string {
	return l.format
}

func (l *logFormatValue) Handler(f io.Writer, opts *slog.HandlerOptions) slog.Handler {
	switch l.format {
	case "text":
		return slog.NewTextHandler(f, opts)
	case "json":
		return slog.NewJSONHandler(f, opts)
	}
	panic(fmt.Sprintf("invalid log format: %s", l.format))
}

type beaconUrlValue struct {
	url.URL
}

func (b *beaconUrlValue) Set(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	b.URL = *u
	return nil
}

func (b *beaconUrlValue) String() string {
	return b.URL.String()
}

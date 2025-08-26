package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service"
)

var (
	port      = flag.Int("port", 8080, "The port to listen on")
	beaconUrl beaconUrlValue
	logLevel  logLevelValue
	logFormat logFormatValue
)

func main() {
	// Initialize non-primitive flags
	flag.Var(&logLevel, "log-level", "The log level to use")
	logLevel.Set("info")
	flag.Var(&logFormat, "log-format", "The log format to use - 'text' or 'json'")
	logFormat.Set("text")
	flag.Var(&beaconUrl, "beacon-url", "The beacon URL to use")
	beaconUrl.Set("http://localhost:5052")
	flag.Parse()

	handler := logFormat.Handler(os.Stdout, &slog.HandlerOptions{Level: logLevel.Level})
	logger := slog.New(handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the beacon client
	beaconClient, err := beacon.NewClient(ctx, logger, logLevel.Level, beaconUrl.String())
	if err != nil {
		logger.Error("Failed to create beacon client", "error", err)
		os.Exit(1)
	}

	svc := service.Service{
		Logger:  logger,
		Context: ctx,
		Port:    *port,
		Beacon:  beaconClient,
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := svc.Run(); err != nil {
			logger.Error("Failed to run service", "error", err)
			os.Exit(1)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled")
			os.Exit(0)
		case <-signalChannel:
			logger.Info("Signal received")
			cancel()
			signal.Reset(os.Interrupt, syscall.SIGTERM)
		}
	}
}

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service/handlers"
)

type Service struct {
	Context  context.Context
	Logger   *slog.Logger
	Port     int
	Host     string
	Listener net.Listener
	Beacon   beacon.BeaconProvider
}

func (s *Service) Run() error {
	var err error

	s.Logger.Info("Starting service", "port", s.Port)

	if s.Listener == nil {
		s.Listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port))
		if err != nil {
			return err
		}
	}

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	byPubkeyHandler := handlers.NewValidatorHandler(s.Logger, s.Beacon)
	serveMux.Handle(byPubkeyHandler.Pattern(), byPubkeyHandler)

	byExecutionAddressHandler := handlers.NewValidatorsHandler(s.Logger, s.Beacon)
	serveMux.Handle(byExecutionAddressHandler.Pattern(), byExecutionAddressHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: serveMux,
	}

	go func() {
		if err := server.Serve(s.Listener); err != nil && err != http.ErrServerClosed {
			s.Logger.Error("Failed to serve", "error", err)
			os.Exit(1)
		}
	}()

	<-s.Context.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)

	s.Logger.Info("Stopping service")
	return nil
}

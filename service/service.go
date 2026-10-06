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
	"github.com/EthStaker/deposit-backend/service/handlers/builder"
	"github.com/EthStaker/deposit-backend/service/handlers/generic"
	"github.com/EthStaker/deposit-backend/service/handlers/validator"
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

	headHandler := generic.NewHeadHandler(s.Logger, s.Beacon)
	serveMux.Handle(headHandler.Pattern(), handlers.NativeHandler(headHandler))

	addressHandler := generic.NewAddressHandler(s.Logger, s.Beacon)
	serveMux.Handle(addressHandler.Pattern(), handlers.NativeHandler(addressHandler))

	byPubkeyHandler := validator.NewValidatorHandler(s.Logger, s.Beacon)
	serveMux.Handle(byPubkeyHandler.Pattern(), handlers.NativeHandler(byPubkeyHandler))

	byExecutionAddressHandler := validator.NewValidatorsHandler(s.Logger, s.Beacon)
	serveMux.Handle(byExecutionAddressHandler.Pattern(), handlers.NativeHandler(byExecutionAddressHandler))

	builderByPubkeyHandler := builder.NewBuilderHandler(s.Logger, s.Beacon)
	serveMux.Handle(builderByPubkeyHandler.Pattern(), handlers.NativeHandler(builderByPubkeyHandler))

	buildersByExecutionAddressHandler := builder.NewBuildersHandler(s.Logger, s.Beacon)
	serveMux.Handle(buildersByExecutionAddressHandler.Pattern(), handlers.NativeHandler(buildersByExecutionAddressHandler))

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

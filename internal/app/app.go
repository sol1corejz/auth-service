package app

import (
	grpcapp "github.com/sol1corejz/auth-service/internal/app/grpc"
	"github.com/sol1corejz/auth-service/internal/services/auth"
	"github.com/sol1corejz/auth-service/internal/storage/postgres"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	tokenTTL time.Duration,
) *App {

	storage, err := postgres.New()
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}

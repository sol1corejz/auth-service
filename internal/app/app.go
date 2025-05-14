package app

import (
	grpcapp "github.com/sol1corejz/auth-service/internal/app/grpc"
	"github.com/sol1corejz/auth-service/internal/services/auth"
	jwt_provider "github.com/sol1corejz/auth-service/internal/services/jwt"
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
	refreshTokenTTL time.Duration,
) *App {

	storage, err := postgres.New()
	if err != nil {
		panic(err)
	}

	jwtProvider := jwt_provider.New(tokenTTL, refreshTokenTTL)

	authService := auth.New(log, storage, storage, storage, jwtProvider, tokenTTL, refreshTokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}

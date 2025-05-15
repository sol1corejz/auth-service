package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/sol1corejz/auth-service/internal/domain/models"
	"github.com/sol1corejz/auth-service/internal/lib/jwt"
	"github.com/sol1corejz/auth-service/internal/lib/logger/sl"
	"github.com/sol1corejz/auth-service/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log             *slog.Logger
	userSaver       UserSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenProvider   TokenProvider
	tokenTTL        time.Duration
	refreshTokenTTL time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid string, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId string) (models.App, error)
}

type TokenProvider interface {
	CheckToken(ctx context.Context, accessToken string, refreshToken string) (models.TokenPair, error)
}

var (
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user exists")
	ErrUserNotFound       = errors.New("user not found")
)

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenProvider TokenProvider,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		userSaver:       userSaver,
		userProvider:    userProvider,
		appProvider:     appProvider,
		tokenProvider:   tokenProvider,
		tokenTTL:        tokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// Login checks if user with given credentials exists in the system
//
// If user exists, but password is incorrect, returns error
// If user doesn`t exists, returns error
func (a *Auth) Login(ctx context.Context, email, password string, appName string) (string, string, error) {
	const op = "auth.LoginUser"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))

			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appName)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully logged in")

	accessToken, refreshToken, err := jwt.NewTokenPair(user, app, a.tokenTTL, a.refreshTokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

// RegisterNewUser registers new user in the system and returns  user ID.
// If user with given username already exists, returns error.
func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (string, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))

		return "", fmt.Errorf("%s, %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", sl.Err(err))

		return "", fmt.Errorf("%s, %w", op, err)
	}

	log.Info("user registered")
	return id, nil
}

// IsAdmin checks if user is admin
func (a *Auth) IsAdmin(ctx context.Context, userID string) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.String("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		log.Error("failed to check if user is admin", sl.Err(err))

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

func (a *Auth) CheckAndRefreshTokens(ctx context.Context, accessToken string, refreshToken string) (bool, string, string, error) {
	const op = "auth.CheckToken"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("checking token pair")

	tokenPair, err := a.tokenProvider.CheckToken(ctx, accessToken, refreshToken)
	if err != nil {
		return false, "", "", ErrInvalidCredentials
	}

	if tokenPair.AccessToken == accessToken {
		return true, "", "", nil
	}

	return true, accessToken, refreshToken, nil
}

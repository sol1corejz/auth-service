package jwt

import (
	"context"
	"github.com/sol1corejz/auth-service/internal/domain/models"
	"github.com/sol1corejz/auth-service/internal/lib/jwt"
	"time"
)

type TokenProvider struct {
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func New(accessTTL, refreshTTL time.Duration) *TokenProvider {
	return &TokenProvider{
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	}
}

func (t *TokenProvider) CheckToken(
	ctx context.Context,
	accessToken string,
	refreshToken string,
) (models.TokenPair, error) {
	valid, tokens, err := jwt.CheckTokens(
		accessToken,
		refreshToken,
		t.AccessTTL,
		t.RefreshTTL,
	)

	if !valid || err != nil {
		return models.TokenPair{}, jwt.ErrAccessDenied
	}

	// Если токены были обновлены, возвращаем новые
	if tokens != nil {
		return *tokens, nil
	}

	// Если оба токена были валидны, возвращаем оригинальные
	return models.TokenPair{}, nil
}

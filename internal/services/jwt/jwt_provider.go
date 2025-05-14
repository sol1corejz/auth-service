package jwt

import (
	"context"
	"github.com/sol1corejz/auth-service/internal/domain/models"
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

	/*
		TODO: реализовать проверку токенов в либе jwt.go и использовать здесь
			1. рефреш валиден и аксес валиден: возвращаем true
			2. рефреш валиден и аксес НЕ валиден: вовзращаем true и новую пару токенов
			3. рефреш НЕ валиден и аксес НЕ валиден: возвращаем false и ошибку (нет доступа)
	*/

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

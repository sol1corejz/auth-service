package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/sol1corejz/auth-service/internal/domain/models"
	log "log/slog"
	"os"
	"time"
)

const (
	jwtAccess  = "JWT_ACCESS_SECRET"
	jwtRefresh = "JWT_REFRESH_SECRET"
)

func NewTokenPair(user models.User, app models.App, accessDuration time.Duration, refreshDuration time.Duration) (string, string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":    user.ID,
		"email":  user.Email,
		"exp":    time.Now().Add(accessDuration).Unix(),
		"app_id": app.ID,
	})

	accessSecret := GetSecretKey(jwtAccess)
	refreshSecret := GetSecretKey(jwtRefresh)

	accessTokenString, err := token.SignedString([]byte(accessSecret))
	if err != nil {
		return "", "", err
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":    user.ID,
		"exp":    time.Now().Add(refreshDuration).Unix(),
		"app_id": app.ID,
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(refreshSecret))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

func RefreshTokenPair(user models.User, app models.App, accessDuration time.Duration, refreshDuration time.Duration, refreshTokenString string) (string, string, error) {
	token, err := validateRefreshToken(refreshTokenString)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	_, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token claims")
	}

	// Генерируем новую пару токенов
	return NewTokenPair(user, app, accessDuration, refreshDuration)
}

func validateRefreshToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(GetSecretKey(jwtRefresh)), nil
	})
}

func GetSecretKey(tokenType string) string {
	// Попробуем прочитать из переменных окружения (для Docker)
	jwtSecret := os.Getenv(tokenType)
	if jwtSecret != "" {
		return jwtSecret
	}

	// Если не найдено в переменных окружения, пробуем .env (для локальной разработки)
	if err := godotenv.Load(); err == nil {
		jwtSecret = os.Getenv(tokenType)
		if jwtSecret != "" {
			return jwtSecret
		}
	}

	log.Error("%s not found in environment or .env file", tokenType)
	return ""
}

package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

var ErrAccessDenied = errors.New("access denied")

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

// CheckTokens проверяет валидность токенов и возвращает:
// 1. Если оба токена валидны: true, текущие токены, nil
// 2. Если refresh валиден, а access нет: true, новые токены, nil
// 3. Если оба невалидны: false, nil, error
func CheckTokens(
	accessToken string,
	refreshToken string,
	accessDuration time.Duration,
	refreshDuration time.Duration,
) (bool, *models.TokenPair, error) {
	// 1. Проверяем access token
	accessValid := validateAccessToken(accessToken)
	isAccessTokenExpired := validateAccessTokenExpiration(refreshToken)
	if !accessValid {
		return false, nil, ErrAccessDenied
	}

	// 2. Проверяем refresh token
	refreshTokenObj, refreshErr := validateRefreshToken(refreshToken)
	refreshValid := refreshErr == nil && refreshTokenObj.Valid

	// Получаем claims из refresh токена (если он валиден)
	var user models.User
	var app models.App
	if refreshValid {
		if claims, ok := refreshTokenObj.Claims.(jwt.MapClaims); ok {
			// Приводим типы, так как jwt возвращает float64 для чисел
			if uid, ok := claims["uid"].(string); ok {
				ID, err := uuid.Parse(uid)
				if err != nil {
					return false, nil, err
				}
				user.ID = ID
			}
			if email, ok := claims["email"].(string); ok {
				user.Email = email
			}
			if appID, ok := claims["app_id"].(string); ok {
				ID, err := uuid.Parse(appID)
				if err != nil {
					return false, nil, err
				}
				app.ID = ID
			}
		}
	}

	// Случай 1: Оба токена валидны
	if !isAccessTokenExpired && refreshValid {
		return true, &models.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}, nil
	}

	// Случай 2: Refresh валиден, access нет
	if refreshValid {
		newAccess, newRefresh, err := NewTokenPair(user, app, accessDuration, refreshDuration)
		if err != nil {
			return false, nil, fmt.Errorf("failed to generate new tokens: %w", err)
		}
		return true, &models.TokenPair{
			AccessToken:  newAccess,
			RefreshToken: newRefresh,
		}, nil
	}

	// Случай 3: Оба токена невалидны
	return false, nil, ErrAccessDenied
}

// Валидация access token
func validateAccessToken(tokenString string) bool {
	claims, err := parseAccessToken(tokenString)
	if err != nil {
		return false
	}

	// Проверка отдельных полей
	if _, ok := claims["uid"].(string); !ok || claims["uid"].(string) == "" {
		return false
	}

	if _, ok := claims["app_id"].(string); !ok || claims["app_id"].(string) == "" {
		return false
	}

	if _, ok := claims["email"].(string); !ok || claims["email"].(string) == "" {
		return false
	}

	return true
}

func validateAccessTokenExpiration(tokenString string) bool {

	claims, err := parseAccessToken(tokenString)
	if err != nil {
		return false
	}

	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() > int64(exp) {
		return false
	}

	return true
}

func parseAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrAccessDenied
		}
		return []byte(GetSecretKey(jwtAccess)), nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, err
	}

	return claims, nil
}

func validateRefreshToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		secret := GetSecretKey(jwtRefresh)
		if secret == "" {
			return nil, fmt.Errorf("refresh token secret not configured")
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return token, nil
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

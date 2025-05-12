package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/sol1corejz/auth-service/internal/domain/models"
	log "log/slog"
	"os"
	"time"
)

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":    user.ID,
		"email":  user.Email,
		"exp":    time.Now().Add(duration).Unix(),
		"app_id": app.ID,
	})

	secret := GetSecretKey()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GetSecretKey() string {
	// Попробуем прочитать из переменных окружения (для Docker)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret != "" {
		return jwtSecret
	}

	// Если не найдено в переменных окружения, пробуем .env (для локальной разработки)
	if err := godotenv.Load(); err == nil {
		jwtSecret = os.Getenv("JWT_SECRET")
		if jwtSecret != "" {
			return jwtSecret
		}
	}

	log.Error("JWT_SECRET not found in environment or .env file")
	return ""
}

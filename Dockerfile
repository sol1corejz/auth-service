# Этап сборки
FROM golang:1.23.2-alpine AS builder
LABEL authors="ilyaparunov"

# Устанавливаем зависимости для сборки
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app

# Копируем только то, что нужно для загрузки зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копируем остальные файлы
COPY . .

# Собираем приложение с CGO
# Собираем оба бинарника в одном RUN (меньше слоев)
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /app/auth-service ./cmd/sso/main.go \
    && CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /app/migrator ./cmd/migrator/main.go

# Финальный образ
FROM alpine:3.18
WORKDIR /app

# Устанавливаем только необходимые зависимости
RUN apk add --no-cache sqlite

# Создаем директорию для базы данных
RUN mkdir -p /app/storage && chmod 777 /app/storage

# Копируем бинарники из builder-этапа
COPY --from=builder /app/auth-service /app/auth-service
COPY --from=builder /app/migrator /app/migrator

# Копируем миграции
COPY --from=builder /app/migrations ./migrations

# Копируем конфиг
COPY --from=builder /app/config ./config

# Создаем пользователя для безопасности
RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app
USER appuser

# Открываем порт
EXPOSE 44044

# Команда запуска
CMD ["sh", "-c", "/app/migrator --storage-path=/app/storage/sso.db --migrations-path=/app/migrations && /app/auth-service --config=./config/local.yaml"]
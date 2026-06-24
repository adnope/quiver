FROM node:24-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend-builder /app/frontend/dist /app/internal/web/dist

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o quiver cmd/quiver/main.go

FROM alpine:3.23

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/quiver /app/quiver

EXPOSE 8080 2055/udp

ENTRYPOINT ["/app/quiver"]

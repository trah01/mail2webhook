# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o mail2webhook main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy from builder
COPY --from=builder /app/mail2webhook /app/mail2webhook

# Expose the dashboard port
EXPOSE 8080

# Run
CMD ["./mail2webhook"]

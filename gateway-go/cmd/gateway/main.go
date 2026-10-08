package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/defence-cyber-portal/integration-gateway/internal/api"
	"github.com/defence-cyber-portal/integration-gateway/internal/idempotency"
	"github.com/defence-cyber-portal/integration-gateway/internal/publisher"
	"github.com/defence-cyber-portal/integration-gateway/internal/ratelimit"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	if webhookSecret == "" {
		webhookSecret = "defence-cyber-portal-secret-key"
	}

	log.Printf("Initializing Defence Cyber Portal - Integration Gateway (Go 1.24+ runtime)")

	// Initialize components
	idempotencyStore := idempotency.NewStore(24 * time.Hour)
	// 1,000 events per minute per source default = ~16.6 tokens/sec, burst 200
	rateLimiter := ratelimit.NewLimiterManager(16.6, 200.0)
	pub := publisher.NewInMemKafkaPublisher(12) // 12 partitions per Section 5.3

	server := api.NewGatewayServer(idempotencyStore, rateLimiter, pub, webhookSecret)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	server.RegisterRoutes(r)

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Integration Gateway listening on http://0.0.0.0:%s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down Integration Gateway gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Graceful shutdown failed: %v", err)
	}
	log.Println("Integration Gateway stopped.")
}

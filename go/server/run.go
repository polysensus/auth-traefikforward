package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

const (
	ConfigName  = "server"
	DefaultPort = 8401
)

type Config struct {
	Address       string
	ShutdownGrace time.Duration
	WriteTimeout  time.Duration
	ReadTimeout   time.Duration
	IdleTimeout   time.Duration
}

func NewConfig() Config {
	cfg := Config{
		Address:       fmt.Sprintf("0.0.0.0:%d", DefaultPort),
		ShutdownGrace: time.Second * 15,
		WriteTimeout:  time.Second * 15,
		ReadTimeout:   time.Second * 15,
		IdleTimeout:   time.Second * 60,
	}
	return cfg
}

type Server struct {
	ConfigFileDir string
	cfg           *Config
}

type Option func(*Server)

func NewServer(
	ctx context.Context, configFileDir string, cfg *Config, opts ...Option) (Server, error) {

	s := Server{
		ConfigFileDir: configFileDir,
		cfg:           cfg,
	}

	for _, opt := range opts {
		opt(&s)
	}
	return s, nil
}

func (s *Server) Serve() {

	// Add your routes as needed
	r := mux.NewRouter()
	h := NewExchanger(s.cfg)
	r.Handle("/exchange", h)

	srv := &http.Server{
		Addr: s.cfg.Address,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: s.cfg.WriteTimeout,
		ReadTimeout:  s.cfg.ReadTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Println("shutting down")
	os.Exit(0)
}

package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	pool    *pgxpool.Pool
	once    sync.Once
	initErr error
)

// Get returns a singleton pgxpool Pool.
// Precedence: TRANSACTION_POOLER → SESSION_POOLER → POSTGRES_URL.
func Get(ctx context.Context) (*pgxpool.Pool, error) {
	once.Do(func() {
		url := os.Getenv("TRANSACTION_POOLER")
		if url == "" {
			url = os.Getenv("SESSION_POOLER")
		}
		if url == "" {
			url = os.Getenv("POSTGRES_URL")
		}
		if url == "" {
			initErr = errors.New("database URL is not set (expected TRANSACTION_POOLER, SESSION_POOLER, or POSTGRES_URL)")
			return
		}
		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			initErr = fmt.Errorf("parse pool config: %w", err)
			return
		}
		// Keep the pool conservative for serverless
		cfg.MaxConns = 3
		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		pool, initErr = pgxpool.NewWithConfig(ctxTimeout, cfg)
	})
	return pool, initErr
}

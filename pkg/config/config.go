package config

import (
	"sync"

	"github.com/joho/godotenv"
)

var once sync.Once

// Init loads .env if present (for local dev). In serverless environments, it is a no-op.
func Init() {
	once.Do(func() {
		_ = godotenv.Load()
	})
}

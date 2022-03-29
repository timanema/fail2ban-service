package main

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/timanema/fail2ban-service/internal/server"
	"github.com/timanema/fail2ban-service/pkg/blocker"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"log"
	"os"
	"os/signal"
	"time"
)

type Config struct {
	server.Config
	StorageType string `default:"memory" split_words:"true"`
}

func main() {
	log.Println("starting server")

	var c Config
	if err := envconfig.Process("fail2ban", &c); err != nil {
		log.Fatalf("unable to load fail2ban server config: %v\n", err)
	}
	log.Printf("active configuration: %+v\n", c)

	var store storage.Storage
	switch c.StorageType {
	case "memory":
		store = storage.NewMemoryStore()
	case "persistent":
		store = storage.NewPersistentStore()
	default:
		log.Printf("invalid storage type: %v, using 'memory' type as fallback\n", c.StorageType)
		store = storage.NewMemoryStore()
	}

	p := store
	s := server.New(p, blocker.Policy{
		Attempts:  3,
		Period:    time.Second * 5,
		BlockTime: time.Minute,
	}, c.Config)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go s.ListenAndServe()

	<-stop
	log.Println("stopping server")

	if err := p.Close(); err != nil {
		log.Printf("failed to close storage: %v\n", err)
	}
	if err := s.Shutdown(); err != nil {
		log.Fatalf("failed to stop server: %v\n", err)
	}
}

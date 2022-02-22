package main

import (
	"github.com/timanema/fail2ban-service/internal/server"
	"github.com/timanema/fail2ban-service/pkg/blocker"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"log"
	"os"
	"os/signal"
	"time"
)

func main() {
	log.Println("starting server")
	s := server.New(storage.NewMemoryStore(), blocker.Policy{
		Attempts:  3,
		Period:    time.Second * 5,
		BlockTime: time.Minute,
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go s.ListenAndServe()

	<-stop
	log.Println("stopping server")
	log.Fatalln(s.Shutdown())
}

package server

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/timanema/fail2ban-service/pkg/blocker"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"github.com/timanema/fail2ban-service/pkg/unix_time"
	"log"
	"math/rand"
	"net/http"
	"time"
)

type Config struct {
	GenerateDebugData bool `default:"true"`
}

type Server struct {
	store   storage.Storage
	blocker *blocker.Blocker
	config  Config

	server *http.Server
}

func New(store storage.Storage, policy blocker.Policy, config Config) *Server {
	s := &Server{
		store:   store,
		blocker: blocker.New(store, policy),
		config:  config,
	}

	if err := s.blocker.NotifyAll(); err != nil {
		log.Fatalf("unable to start blocker: %v\n", err)
	}

	if s.config.GenerateDebugData {
		go s.generateDebugData()
	}

	return s
}

func (s *Server) ListenAndServe() {
	router := mux.NewRouter().StrictSlash(true)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/blocked/{ip}", s.blockedQuery).Methods(http.MethodGet)
	apiRouter.HandleFunc("/block/{ip}", s.block).Methods(http.MethodPost)
	apiRouter.HandleFunc("/unblock/{ip}", s.unblock).Methods(http.MethodPost)
	apiRouter.HandleFunc("/blocks", s.listBlocks).Methods(http.MethodGet)
	apiRouter.HandleFunc("/policy", s.getPolicy).Methods(http.MethodGet)
	apiRouter.HandleFunc("/policy", s.updatePolicy).Methods(http.MethodPatch)
	apiRouter.HandleFunc("/modules", s.getExternalModules).Methods(http.MethodGet)
	apiRouter.HandleFunc("/module", s.addExternalModule).Methods(http.MethodPut)
	apiRouter.HandleFunc("/module/{id}", s.removeExternalModule).Methods(http.MethodDelete)

	entryRouter := apiRouter.PathPrefix("/entries").Subrouter()
	entryRouter.HandleFunc("/", s.listSources)
	entryRouter.HandleFunc("/list/{ip}", s.listEntries).Methods(http.MethodGet)
	entryRouter.HandleFunc("/add/{ip}", s.addEntry).Methods(http.MethodPut)

	c := cors.New(cors.Options{
		AllowedMethods:   []string{"GET", "POST", "OPTIONS", "PATCH", "HEAD", "PUT"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	})

	s.server = &http.Server{Addr: ":8080", Handler: c.Handler(router)}

	log.Fatalln(s.server.ListenAndServe())
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

func (s *Server) generateDebugData() {
	log.Printf("generation of debug data is enabled, generating 10 random entries")
	for i := 0; i < 10; i++ {
		entry := storage.BlockEntry{
			Source:    fmt.Sprintf("%v.%v.%v.%v", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)),
			Timestamp: unix_time.Time(time.Now()),
			Duration:  time.Minute*time.Duration(rand.Intn(5)) + time.Second*time.Duration(rand.Intn(60)),
		}

		if err := s.store.AddBlockEntry(entry); err != nil {
			log.Printf("unable to add debug block entry: %v\n", err)
		}
	}
}

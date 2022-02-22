package server

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/timanema/fail2ban-service/pkg/blocker"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"log"
	"net/http"
	"time"
)

type Server struct {
	store   storage.Storage
	blocker *blocker.Blocker

	server *http.Server
}

func New(store storage.Storage, policy blocker.Policy) *Server {
	s := &Server{
		store:   store,
		blocker: blocker.New(store, policy),
	}

	err := s.blocker.NotifyAll()
	if err != nil {
		log.Fatalf("unable to start blocker: %v\n\n", err)
	}

	return s
}

func (s *Server) ListenAndServe() {
	router := mux.NewRouter().StrictSlash(true)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/blocked/{ip}", s.blockedQuery).Methods(http.MethodGet)
	apiRouter.HandleFunc("/block/{ip}", s.block).Methods(http.MethodPost)
	apiRouter.HandleFunc("/unblock/{ip}", s.unblock).Methods(http.MethodPost)
	apiRouter.HandleFunc("/policy", s.getPolicy).Methods(http.MethodGet)
	apiRouter.HandleFunc("/policy", s.updatePolicy).Methods(http.MethodPatch)
	apiRouter.HandleFunc("/modules", s.getExternalModules).Methods(http.MethodGet)
	apiRouter.HandleFunc("/module", s.addExternalModule).Methods(http.MethodPut)
	apiRouter.HandleFunc("/module/{id}", s.removeExternalModule).Methods(http.MethodDelete)

	entryRouter := apiRouter.PathPrefix("/entries").Subrouter()
	entryRouter.HandleFunc("/", s.listSources)
	entryRouter.HandleFunc("/list/{ip}", s.listEntries).Methods(http.MethodGet)
	entryRouter.HandleFunc("/add/{ip}", s.addEntry).Methods(http.MethodPut)

	s.server = &http.Server{Addr: ":8080", Handler: router}

	log.Fatalln(s.server.ListenAndServe())
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

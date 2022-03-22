package server

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/timanema/fail2ban-service/pkg/blocker"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
)

func writeError(err error, w http.ResponseWriter, code int) {
	w.WriteHeader(code)
	fmt.Fprintf(w, "%v, %v", code, http.StatusText(code))
	log.Printf("error: %v\n", err)
}

func writeSuccess(w http.ResponseWriter) {
	res := struct {
		Success bool `json:"success"`
	}{
		Success: true,
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) listSources(w http.ResponseWriter, _ *http.Request) {
	sources, err := s.store.FindSources()
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(sources); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) listBlocks(w http.ResponseWriter, _ *http.Request) {
	activeBlocks, err := s.store.AllBlockEntries(true)
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(activeBlocks); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) listEntries(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	entries, err := s.store.FindAuthenticationEntries(ip)
	if err != nil && err != storage.NotFoundErr {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	res := make([]storage.AuthenticationEntry, 0, len(entries))
	for e := range entries {
		res = append(res, e)
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) addEntry(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeError(err, w, http.StatusBadRequest)
		return
	}

	var entry storage.AuthenticationEntry
	if err := json.Unmarshal(buf, &entry); err != nil {
		writeError(err, w, http.StatusBadRequest)
		return
	}

	if !entry.Valid() || entry.Source != ip {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v bad request, invalid entry data", http.StatusBadRequest)
		return
	}

	if err := s.blocker.AddEntry(entry); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
	writeSuccess(w)
}

func (s *Server) blockedQuery(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]

	blocked, entry, err := s.blocker.IsBlocked(ip)
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	res := struct {
		Blocked bool                `json:"blocked"`
		Entry   *storage.BlockEntry `json:"entry,omitempty"`
	}{
		Blocked: blocked,
		Entry:   &entry,
	}
	if !blocked {
		res.Entry = nil
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) block(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]

	entry, err := s.blocker.BlockIP(ip)
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(entry); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]

	if blocked, _, _ := s.blocker.IsBlocked(ip); !blocked {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v bad request, %v is not blocked", http.StatusBadRequest, ip)
		return
	}

	if err := s.blocker.UnblockIP(ip); err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	writeSuccess(w)
}

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	if err := json.NewEncoder(w).Encode(s.blocker.Policy()); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	var policy blocker.Policy
	if err := json.Unmarshal(buf, &policy); err != nil {
		writeError(err, w, http.StatusBadRequest)
		return
	}

	s.blocker.UpdatePolicy(policy)
	writeSuccess(w)
}

func (s *Server) getExternalModules(w http.ResponseWriter, _ *http.Request) {
	modules, err := s.store.GetExternalModules()
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(modules); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) addExternalModule(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	var module storage.ExternalModule
	if err := json.Unmarshal(buf, &module); err != nil {
		writeError(err, w, http.StatusBadRequest)
		return
	}

	module.Id = rand.Uint32()

	existingModule, err := s.store.GetExternalModuleByAddress(module.Address)
	if err != nil && err != storage.NotFoundErr {
		writeError(err, w, http.StatusInternalServerError)
		return
	}
	if err != storage.NotFoundErr {
		module.Id = existingModule.Id
	}

	if err := s.store.AddExternalModule(module); err != nil {
		writeError(err, w, http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(module); err != nil {
		writeError(err, w, http.StatusInternalServerError)
	}
}

func (s *Server) removeExternalModule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v bad request, %v is not a valid number", http.StatusBadRequest, id)
		return
	}

	if err := s.store.RemoveExternalModule(uint32(id)); err != nil {
		writeError(err, w, http.StatusInternalServerError)
		return
	}

	writeSuccess(w)
}

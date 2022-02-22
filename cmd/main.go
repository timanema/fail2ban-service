package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/timanema/fail2ban-service/pkg/storage"
	"io/ioutil"
	"log"
	"net/http"
)

type Test struct {
	Msg string `json:"msg"`
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: "test message"})
}

func listEntries(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: ip})
}

func addEntry(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var entry storage.AuthenticationEntry
	if err := json.Unmarshal(buf, &entry); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !entry.Valid() {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v bad request, invalid entry data", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: ip})
}

func blockedQuery(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: ip})
}

func block(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: ip})
}

func unblock(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: ip})
}

func getPolicy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: "test message"})
}

func updatePolicy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Test{Msg: "test message"})
}

func main() {
	fmt.Println("test")

	router := mux.NewRouter().StrictSlash(true)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/", handleMain)
	apiRouter.HandleFunc("/blocked/{ip}", blockedQuery).Methods(http.MethodGet)
	apiRouter.HandleFunc("/block/{ip}", block).Methods(http.MethodPost)
	apiRouter.HandleFunc("/unblock/{ip}", unblock).Methods(http.MethodPost)
	apiRouter.HandleFunc("/policy", getPolicy).Methods(http.MethodGet)
	apiRouter.HandleFunc("/policy", updatePolicy).Methods(http.MethodPatch)

	entryRouter := apiRouter.PathPrefix("/entries").Subrouter()
	entryRouter.HandleFunc("/", handleMain)
	entryRouter.HandleFunc("/list/{ip}", listEntries).Methods(http.MethodGet)
	entryRouter.HandleFunc("/add/{ip}", addEntry).Methods(http.MethodGet)

	log.Fatalln(http.ListenAndServe(":8080", router))
}

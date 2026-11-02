// A small Go web service with a React frontend in web/: Lantern's Go sample.
package main

import (
	"log"
	"net/http"

	"example.com/goapp/internal/store"
)

type Server struct {
	repo  store.Repo
	mails Mailer
}

type Mailer interface {
	Send(to, body string) error
}

func newServer(repo store.Repo) *Server {
	return &Server{repo: repo, mails: &SMTPMailer{}}
}

func main() {
	db := store.Open("notes.db")
	s := newServer(db)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/notes/{id}", s.getNote)
	mux.HandleFunc("POST /api/notes", s.createNote)
	mux.HandleFunc("DELETE /api/notes/{id}", s.deleteNote)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}

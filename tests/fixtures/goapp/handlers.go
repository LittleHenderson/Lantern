package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
)

func (s *Server) getNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.repo.Get(id)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	json.NewEncoder(w).Encode(n)
}

func (s *Server) createNote(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user == "" {
		http.Error(w, "login required", 401)
		return
	}
	var in struct{ Text string }
	json.NewDecoder(r.Body).Decode(&in)
	n := s.repo.Save(user, in.Text)
	s.mails.Send(user, "saved: "+n.Text)
	exportNote(n.Text)
	json.NewEncoder(w).Encode(n)
}

func (s *Server) deleteNote(w http.ResponseWriter, r *http.Request) {
	s.repo.Delete(r.PathValue("id"))
	w.WriteHeader(204)
}

func currentUser(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

// exportNote runs a shell command with user text in it.
func exportNote(text string) {
	exec.Command("sh", "-c", "echo "+text+" >> export.txt").Run()
}

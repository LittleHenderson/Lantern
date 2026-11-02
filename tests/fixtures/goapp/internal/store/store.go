package store

import "database/sql"

type Note struct {
	ID   string
	User string
	Text string
}

type Repo interface {
	Get(id string) (*Note, error)
	Save(user, text string) *Note
	Delete(id string)
}

type SQLStore struct {
	db *sql.DB
}

func Open(path string) *SQLStore {
	db, _ := sql.Open("sqlite", path)
	return &SQLStore{db: db}
}

func (s *SQLStore) Get(id string) (*Note, error) {
	row := s.db.QueryRow("SELECT id, user, text FROM notes WHERE id = " + id)
	n := &Note{}
	err := row.Scan(&n.ID, &n.User, &n.Text)
	return n, err
}

func (s *SQLStore) Save(user, text string) *Note {
	s.db.Exec("INSERT INTO notes(user, text) VALUES (?, ?)", user, text)
	return &Note{User: user, Text: text}
}

func (s *SQLStore) Delete(id string) {
	s.db.Exec("DELETE FROM notes WHERE id = ?", id)
}

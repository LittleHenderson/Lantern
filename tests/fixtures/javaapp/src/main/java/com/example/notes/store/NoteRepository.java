package com.example.notes.store;

public interface NoteRepository {
    Note find(String id);

    Note save(String user, String text);

    void delete(String id);
}

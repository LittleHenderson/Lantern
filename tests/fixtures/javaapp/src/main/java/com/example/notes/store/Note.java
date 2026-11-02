package com.example.notes.store;

public class Note {
    private final String id;
    private final String user;
    private final String text;

    public Note(String id, String user, String text) {
        this.id = id;
        this.user = user;
        this.text = text;
    }

    public String getText() {
        return text;
    }
}

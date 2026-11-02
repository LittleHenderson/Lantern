package com.example.notes.store;

import org.junit.jupiter.api.Test;

class SqlNoteRepositoryTest {
    @Test
    void savesANote() {
        SqlNoteRepository repo = new SqlNoteRepository(null);
        Note n = repo.save("ann", "hi");
        assert n.getText().equals("hi");
    }
}

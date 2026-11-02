package com.example.notes.store;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SqlNoteRepository implements NoteRepository {
    private final Connection conn;

    public SqlNoteRepository(Connection conn) {
        this.conn = conn;
    }

    @Override
    public Note find(String id) {
        try (Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT id, user, text FROM notes WHERE id = " + id);
            if (rs.next()) {
                return new Note(rs.getString(1), rs.getString(2), rs.getString(3));
            }
        } catch (SQLException e) {
            return null;
        }
        return null;
    }

    @Override
    public Note save(String user, String text) {
        return new Note("1", user, text);
    }

    @Override
    public void delete(String id) {
        // DELETE FROM notes WHERE id = ?
    }
}

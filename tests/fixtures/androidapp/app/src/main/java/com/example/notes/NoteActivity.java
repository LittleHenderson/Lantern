package com.example.notes;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class NoteActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String id = getIntent().getData().getQueryParameter("id");
        show(id);
    }

    void show(String id) {
        SQLiteDatabase db = openOrCreateDatabase("notes.db", MODE_PRIVATE, null);
        Cursor c = db.rawQuery("SELECT title FROM notes WHERE id = " + id, null);
        c.close();
    }
}

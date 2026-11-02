package com.example.notes.web;

import com.example.notes.mail.Mailer;
import com.example.notes.mail.SmtpMailer;
import com.example.notes.store.Note;
import com.example.notes.store.NoteRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/notes")
public class NoteController {
    private final NoteRepository repo;
    private final Mailer mailer = new SmtpMailer();

    public NoteController(NoteRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/{id}")
    public Note getNote(@PathVariable String id) {
        return repo.find(id);
    }

    @PostMapping
    public Note createNote(@RequestHeader("X-Session") String session, @RequestBody String text) {
        String user = currentUser(session);
        if (user.isEmpty()) {
            throw new IllegalStateException("login required");
        }
        Note n = repo.save(user, text);
        mailer.send(user, n.getText());
        Exporter.export(n.getText());
        return n;
    }

    @DeleteMapping("/{id}")
    public void deleteNote(@PathVariable String id) {
        repo.delete(id);
    }

    private String currentUser(String session) {
        return session == null ? "" : session;
    }
}

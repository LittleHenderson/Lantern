package com.example.notes.mail;

public interface Mailer {
    boolean send(String to, String body);
}

package com.example.notes.mail;

public class SmtpMailer implements Mailer {
    @Override
    public boolean send(String to, String body) {
        return true;
    }
}

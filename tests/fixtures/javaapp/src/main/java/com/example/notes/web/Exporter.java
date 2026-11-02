package com.example.notes.web;

import java.io.IOException;

public class Exporter {
    /** Runs a shell command with user text in it. */
    public static void export(String text) {
        try {
            Runtime.getRuntime().exec("sh -c \"echo " + text + " >> export.txt\"");
        } catch (IOException e) {
            // ignored
        }
    }
}

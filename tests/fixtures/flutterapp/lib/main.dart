import 'package:flutter/material.dart';
import 'links.dart';
import 'screens/home_screen.dart';
import 'screens/note_screen.dart';

void main() {
  runApp(const NotesApp());
  Links.listen();
}

class NotesApp extends StatelessWidget {
  const NotesApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: const HomeScreen(),
      routes: {'/note': (context) => const NoteView(id: '1')},
    );
  }
}

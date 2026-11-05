import 'package:flutter/material.dart';
import '../data/note_db.dart';

class NoteView extends StatelessWidget {
  const NoteView({super.key, required this.id});
  final String id;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder(future: NoteDb().find(id), builder: (c, s) => Text('${s.data}'));
  }
}

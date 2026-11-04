import 'dart:io';
import 'package:sqflite/sqflite.dart';

class NoteDb {
  Future<Database> open() => openDatabase('notes.db');

  Future<List<String>> all() async {
    final db = await open();
    final rows = await db.query('notes');
    return rows.map((r) => r['title'] as String).toList();
  }

  Future<String?> find(String id) async {
    final db = await open();
    final rows = await db.rawQuery("SELECT title FROM notes WHERE id = '$id'");
    return rows.isEmpty ? null : rows.first['title'] as String;
  }

  void sync() {
    final client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    client.getUrl(Uri.parse('http://api.example.com/sync'));
  }
}

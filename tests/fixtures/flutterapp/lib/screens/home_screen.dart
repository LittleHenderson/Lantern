import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../data/note_db.dart';
import 'note_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final db = NoteDb();
  List<String> notes = [];

  Future<void> _load() async {
    notes = await db.all();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('authToken', 'abc');
    print('loaded with token ${prefs.getString('authToken')}');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: ListView(children: notes.map((n) => NoteTile(title: n)).toList()),
      floatingActionButton: FloatingActionButton(onPressed: _load),
    );
  }
}

class NoteTile extends StatelessWidget {
  const NoteTile({super.key, required this.title});
  final String title;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      title: Text(title),
      onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => NoteView(id: title))),
    );
  }
}

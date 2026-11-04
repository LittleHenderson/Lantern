import 'package:app_links/app_links.dart';
import 'data/note_db.dart';

class Links {
  static void listen() {
    AppLinks().uriLinkStream.listen((uri) {
      openNote(uri);
    });
  }

  static Future<void> openNote(Uri uri) async {
    final id = uri.queryParameters['id'] ?? '';
    await NoteDb().find(id);
  }
}

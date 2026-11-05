#include "note_store.h"
#include <cstdio>

namespace notes {

NoteStore::NoteStore(const std::string& path) {
  sqlite3_open(path.c_str(), &db_);
}

std::string NoteStore::search(const std::string& q) {
  char sql[512];
  snprintf(sql, sizeof(sql), "SELECT title FROM notes WHERE title LIKE '%%%s%%'", q.c_str());
  sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);
  return "[]";
}

bool NoteStore::remove(int id) {
  sqlite3_stmt* stmt = nullptr;
  sqlite3_prepare_v2(db_, "DELETE FROM notes WHERE id = ?", -1, &stmt, nullptr);
  sqlite3_bind_int(stmt, 1, id);
  return sqlite3_step(stmt) == SQLITE_DONE;
}

}  // namespace notes

#pragma once
#include <string>
#include <sqlite3.h>

namespace notes {

class NoteStore {
 public:
  explicit NoteStore(const std::string& path);
  std::string search(const std::string& q);
  bool remove(int id);

 private:
  sqlite3* db_ = nullptr;
};

}  // namespace notes

#include <cstdlib>
#include <string>
#include "httplib.h"
#include "note_store.h"

static std::string archive_name(const std::string& name) {
  return "/tmp/" + name + ".tgz";
}

int main() {
  httplib::Server svr;
  notes::NoteStore store("notes.db");

  svr.Get("/api/notes/search", [&](const httplib::Request& req, httplib::Response& res) {
    std::string q = req.get_param_value("q");
    res.set_content(store.search(q), "application/json");
  });

  svr.Delete("/api/notes/:id", [&](const httplib::Request& req, httplib::Response& res) {
    store.remove(std::stoi(req.path_params.at("id")));
    res.status = 204;
  });

  svr.Post("/api/export", [&](const httplib::Request& req, httplib::Response& res) {
    std::string name = req.get_param_value("name");
    std::string cmd = "tar czf " + archive_name(name) + " notes.db";
    std::system(cmd.c_str());
    res.set_content("ok", "text/plain");
  });

  svr.listen("0.0.0.0", 8080);
  return 0;
}

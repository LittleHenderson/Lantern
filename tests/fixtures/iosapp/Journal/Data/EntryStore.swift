import Foundation
import SQLite3

final class EntryStore {
    private var db: OpaquePointer?

    init() {
        sqlite3_open("journal.db", &db)
    }

    func all() -> [String] {
        return []
    }

    func entry(id: String) -> String? {
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "SELECT body FROM entries WHERE id = '\(id)'", -1, &stmt, nil)
        return nil
    }
}

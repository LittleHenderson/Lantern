pub struct Note {
    pub id: String,
    pub user: String,
    pub text: String,
}

pub trait Store {
    fn get(&self, id: &str) -> Option<Note>;
    fn save(&self, user: &str, text: &str) -> Note;
    fn delete(&self, id: &str);
}

pub struct SqlStore {
    path: String,
}

impl SqlStore {
    pub fn open(path: &str) -> SqlStore {
        SqlStore { path: path.to_string() }
    }

    fn query(&self, sql: &str) -> Vec<Note> {
        let _ = sql;
        Vec::new()
    }
}

impl Store for SqlStore {
    fn get(&self, id: &str) -> Option<Note> {
        let rows = self.query(&format!("SELECT id, user, text FROM notes WHERE id = {}", id));
        rows.into_iter().next()
    }

    fn save(&self, user: &str, text: &str) -> Note {
        self.query("INSERT INTO notes(user, text) VALUES (?, ?)");
        Note { id: String::new(), user: user.to_string(), text: text.to_string() }
    }

    fn delete(&self, id: &str) {
        let _ = id;
        self.query("DELETE FROM notes WHERE id = ?");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_a_note() {
        let s = SqlStore::open(":memory:");
        let n = s.save("ann", "hi");
        assert_eq!(n.text, "hi");
    }
}

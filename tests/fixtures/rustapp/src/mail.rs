pub trait Mailer: Send + Sync {
    fn send(&self, to: &str, body: &str) -> bool;
}

pub struct Smtp {}

impl Mailer for Smtp {
    fn send(&self, _to: &str, _body: &str) -> bool {
        true
    }
}

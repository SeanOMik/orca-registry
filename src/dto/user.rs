pub struct User {
    username: String,
    email: String,
}

impl User {
    pub fn new(username: String, email: String) -> Self {
        Self {
            username,
            email,
        }
    }
}
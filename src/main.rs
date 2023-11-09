use symciph::App;

fn main() {
    if let Err(err) = App::new().run() {
        eprint!("Error: {}", err);
    }
}

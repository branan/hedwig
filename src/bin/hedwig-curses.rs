#[cfg(feature = "curses")]
fn main() {
    println!("The ncurses frontend has not yet been built");
}

#[cfg(not(feature = "curses"))]
fn main() {
    println!("Hedwig was built without ncurses support");
    std::process::exit(1);
}

#[cfg(feature = "gtk3")]
fn main() {
    println!("The GTK frontend has not yet been built");
}

#[cfg(not(feature = "gtk3"))]
fn main() {
    println!("Hedwig was built without GTK support");
    std::process::exit(1);
}

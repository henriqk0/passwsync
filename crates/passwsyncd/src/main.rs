#![forbid(unsafe_code)]

use passwsyncd::app::{Deps, run};

fn main() {
    let code = run(std::env::args_os().skip(1).collect(), Deps::production());
    std::process::exit(code);
}

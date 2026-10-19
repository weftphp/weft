//! Compiles the C shim against the headers of the PHP that `php-config` points at
//! (override with the `PHP_CONFIG` environment variable).

use std::process::Command;

fn main() {
    let php_config = std::env::var("PHP_CONFIG").unwrap_or_else(|_| "php-config".into());
    println!("cargo:rerun-if-env-changed=PHP_CONFIG");
    println!("cargo:rerun-if-changed=shim/shim.c");

    let out = Command::new(&php_config)
        .arg("--includes")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {php_config}: {e}"));
    assert!(out.status.success(), "{php_config} --includes failed");

    let mut build = cc::Build::new();
    build.file("shim/shim.c").define("COMPILE_DL_WEFT", "1");
    for flag in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        build.flag(flag);
    }
    build.flag_if_supported("-fvisibility=default");
    build.warnings(false);
    build.compile("weft_shim");

    // The Zend symbols are provided by the PHP binary that loads the module.
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}

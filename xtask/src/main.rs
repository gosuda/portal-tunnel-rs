//! Workspace task runner. Reserved for codegen, release, openapi-export,
//! dep-audit, and refresh-frontend-bundle commands. Phase 0 ships a stub.

fn main() {
    let task = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "help".to_string());
    println!("xtask: '{task}' not yet implemented");
}

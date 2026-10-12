//! Embedded Lua compiles configuration into typed rules, never runs on each query.
use anyhow::{Context, Result, ensure};
use mlua::{HookTriggers, Lua, LuaOptions, LuaSerdeExt, StdLib, VmState};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_SCRIPT_BYTES: usize = 32 * 1024;
const MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024;
const MAX_INSTRUCTIONS: u32 = 100_000;

pub fn compile_lua(script: &str) -> Result<guard_core::RuleSet> {
    ensure!(
        script.len() <= MAX_SCRIPT_BYTES,
        "Lua script exceeds 32 KiB"
    );
    let lua = Lua::new_with(
        StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )?;
    lua.set_memory_limit(MAX_MEMORY_BYTES)?;
    for name in [
        "os",
        "io",
        "package",
        "debug",
        "coroutine",
        "require",
        "dofile",
        "loadfile",
        "load",
        "collectgarbage",
        "print",
    ] {
        lua.globals().set(name, mlua::Value::Nil)?;
    }
    let started = Instant::now();
    let executed = Arc::new(AtomicU32::new(0));
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_, _| {
            let count = executed.fetch_add(1000, Ordering::Relaxed) + 1000;
            if count > MAX_INSTRUCTIONS || started.elapsed() > Duration::from_millis(50) {
                return Err(mlua::Error::RuntimeError(
                    "Lua configuration execution budget exceeded".into(),
                ));
            }
            Ok(VmState::Continue)
        },
    )?;
    let value = lua
        .load(script)
        .set_mode(mlua::ChunkMode::Text)
        .set_name("guard-rules")
        .eval::<mlua::Value>()
        .context("Lua configuration failed")?;
    let mut rules: guard_core::RuleSet = lua
        .from_value(value)
        .context("Lua must return a typed rules table")?;
    rules.validate()?;
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiles_table_and_has_no_host_access() {
        let rules = compile_lua("assert(os == nil and io == nil and require == nil and load == nil); return { version = 1, rules = {} }").unwrap();
        assert!(rules.rules.is_empty());
        assert!(compile_lua("return { version=1, rules={}, unexpected=true }").is_err());
    }
    #[test]
    fn instruction_and_memory_budgets() {
        assert!(compile_lua("while true do end").is_err());
        assert!(
            compile_lua(
                "local s = string.rep('x', 8 * 1024 * 1024); return { version=1, rules={} }"
            )
            .is_err()
        );
        assert!(compile_lua(&"x".repeat(MAX_SCRIPT_BYTES + 1)).is_err());
    }
}

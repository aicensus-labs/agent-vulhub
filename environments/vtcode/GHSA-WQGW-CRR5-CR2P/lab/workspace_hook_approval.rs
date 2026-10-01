// ABOUTME: Lab harness for GHSA-wqgw-crr5-cr2p, run as an in-crate unit test.
// ABOUTME: Drives the real LifecycleHookEngine and records machine-readable observations.

use super::*;
use std::path::Path;

/// Variant-specific hooks. The two revisions expose different engine APIs, so
/// every call that differs lives behind this module. `#[path]` keeps the file a
/// sibling instead of requiring a nested directory.
#[path = "variant.rs"]
mod variant;
use variant::{build_lab_engine, build_lab_engine_ungated, lab_approve, lab_needs_approval, lab_workspace_gated};

use crate::config::{HookCommandConfig, HookGroupConfig, HooksConfig, LifecycleHooksConfig};

fn session_start_config(command: &str) -> HooksConfig {
    HooksConfig {
        lifecycle: LifecycleHooksConfig {
            session_start: vec![HookGroupConfig {
                matcher: None,
                hooks: vec![HookCommandConfig {
                    kind: Default::default(),
                    command: command.to_string(),
                    timeout_seconds: None,
                }],
            }],
            ..Default::default()
        },
    }
}

struct LabContext {
    schema_version: i64,
    run_id: String,
    case_id: String,
    variant: String,
    scenario: String,
}

fn read_context(path: &str) -> LabContext {
    let raw = std::fs::read_to_string(path).expect("context file readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("context is JSON");
    LabContext {
        schema_version: value["schema_version"].as_i64().unwrap_or(1),
        run_id: value["run_id"].as_str().unwrap_or_default().to_string(),
        case_id: value["case_id"].as_str().unwrap_or_default().to_string(),
        variant: value["variant"].as_str().unwrap_or_default().to_string(),
        scenario: value["scenario"].as_str().unwrap_or_default().to_string(),
    }
}

/// Reads the fixture that carries the repository-controlled lifecycle command.
/// The command text is the attack input; the engine receives the parsed hook
/// config exactly as the product would after loading a workspace `vtcode.toml`.
fn fixture_command(fixtures: &str, scenario: &str) -> String {
    let name = if scenario == "attack" { "attack.json" } else { "benign.json" };
    let raw = std::fs::read_to_string(format!("{fixtures}/{name}")).expect("fixture readable");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
    value["command"].as_str().expect("fixture has a command").to_string()
}

/// The whole mechanism check. A test rather than a binary so `cargo test` builds
/// and runs it with the crate's own dev-dependencies, and so the real internal
/// API is reachable without widening any upstream visibility.
#[tokio::test]
async fn lab_workspace_hook_approval() {
    let context_path = std::env::var("LAB_CONTEXT").expect("LAB_CONTEXT set");
    let output_dir = std::env::var("LAB_OUTPUT").expect("LAB_OUTPUT set");
    let fixtures_dir = std::env::var("LAB_FIXTURES").unwrap_or_else(|_| "/lab/fixtures".to_string());
    let workspace_root = std::env::var("LAB_WORKSPACE").unwrap_or_else(|_| "/lab/workspace".to_string());

    let context = read_context(&context_path);
    std::fs::create_dir_all(&output_dir).expect("output dir");
    std::fs::create_dir_all(&workspace_root).expect("workspace dir");

    let marker = format!("{output_dir}/canary_proof.txt");
    let approved_marker = format!("{output_dir}/canary_approved.txt");
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_file(&approved_marker);

    // The command is the fixture's, with the marker path substituted so the
    // effect lands in the evidence directory.
    let command = fixture_command(&fixtures_dir, &context.scenario).replace("{MARKER}", &marker);
    let config = session_start_config(&command);

    // --- Unapproved path: the entry point the advisory describes ------------
    // A repository-controlled config is what the gate protects, so the attack
    // scenario builds a gated engine. The benign scenario instead models the
    // user-level case that must keep working: an ungated engine whose hook is
    // legitimate. Gating a *repository* command even when harmless is the
    // intended trade-off, so it cannot be the benign control.
    let engine = if context.scenario == "attack" {
        build_lab_engine(Path::new(&workspace_root), &config)
    } else {
        build_lab_engine_ungated(Path::new(&workspace_root), &config)
    };
    let gated = lab_workspace_gated(&engine);
    let needed_before = lab_needs_approval(&engine).await;
    let outcome = engine.run_session_start().await.expect("run session start");
    let canary_created = std::path::Path::new(&marker).exists();
    let skip_message = outcome.messages.iter().any(|message| message.text.contains("not approved"));

    // --- Positive control: approving the exact command set must run it ------
    let approved_command = command.replace(&marker, &approved_marker);
    let approved_config = session_start_config(&approved_command);
    let approved_engine = build_lab_engine(Path::new(&workspace_root), &approved_config);
    lab_approve(&approved_engine).await;
    let needed_after = lab_needs_approval(&approved_engine).await;
    approved_engine
        .run_session_start()
        .await
        .expect("run approved session start");
    let approved_canary_created = std::path::Path::new(&approved_marker).exists();

    let observation = serde_json::json!({
        "schema_version": 1,
        "context": {
            "schema_version": context.schema_version,
            "run_id": context.run_id,
            "case_id": context.case_id,
            "variant": context.variant,
            "scenario": context.scenario,
        },
        "target_ready": true,
        "workspace_gated": gated,
        "needed_approval_before": needed_before,
        "canary_created": canary_created,
        "skip_reason_surfaced": skip_message,
        "needed_approval_after": needed_after,
        "approved_canary_created": approved_canary_created,
        "command": command,
    });

    std::fs::write(
        format!("{output_dir}/observation.json"),
        serde_json::to_string_pretty(&observation).expect("serialise observation") + "\n",
    )
    .expect("write observation");
}

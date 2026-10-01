// ABOUTME: Vulnerable-variant hooks for the GHSA-wqgw-crr5-cr2p lab harness.
// ABOUTME: Before the fix the engine has no workspace gate, so hooks always run.

use std::path::Path;

use super::super::{LifecycleHookEngine, SessionStartTrigger};
use crate::config::HooksConfig;

/// The vulnerable revision has no workspace gate: `LifecycleHookEngine` exposes
/// neither a gated constructor nor an approval step, and `run_session_start`
/// executes every configured hook. The shared four-argument constructor is the
/// same call the product makes.
pub(crate) fn build_lab_engine(workspace: &Path, config: &HooksConfig) -> LifecycleHookEngine {
    LifecycleHookEngine::new_with_session(
        workspace.to_path_buf(),
        config,
        SessionStartTrigger::Startup,
        "lab-session",
    )
    .expect("engine constructs")
    .expect("non-empty hooks config produces an engine")
}

/// No gate exists, so nothing is ever gated.
pub(crate) fn lab_workspace_gated(_engine: &LifecycleHookEngine) -> bool {
    false
}

/// No approval is ever required, which is the vulnerability.
pub(crate) async fn lab_needs_approval(_engine: &LifecycleHookEngine) -> bool {
    false
}

/// There is no approval store to write to, so the positive control cannot open a
/// gate here.
pub(crate) async fn lab_approve(_engine: &LifecycleHookEngine) {}

/// The pre-fix engine has no gate, so the shared constructor is already ungated.
/// The benign scenario uses this to show user-level hooks still run.
pub(crate) fn build_lab_engine_ungated(workspace: &Path, config: &HooksConfig) -> LifecycleHookEngine {
    build_lab_engine(workspace, config)
}

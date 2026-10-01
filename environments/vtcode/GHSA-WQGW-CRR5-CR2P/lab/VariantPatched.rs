// ABOUTME: Patched-variant hooks for the GHSA-wqgw-crr5-cr2p lab harness.
// ABOUTME: Delegates to the upstream workspace gate introduced by the fix.

use std::path::Path;

use super::super::{LifecycleHookEngine, SessionStartTrigger};
use crate::config::HooksConfig;

/// The patched revision gates the whole engine whenever workspace-controlled
/// hook content is present, so the harness asks for the gated constructor.
pub(crate) fn build_lab_engine(workspace: &Path, config: &HooksConfig) -> LifecycleHookEngine {
    LifecycleHookEngine::new_with_session_gated(
        workspace.to_path_buf(),
        config,
        SessionStartTrigger::Startup,
        "lab-session",
        true,
    )
    .expect("engine constructs")
    .expect("non-empty hooks config produces an engine")
}

/// Asks the real upstream gate rather than the lab's own idea of gating.
pub(crate) fn lab_workspace_gated(engine: &LifecycleHookEngine) -> bool {
    engine.workspace_gated()
}

/// Asks the real upstream gate whether approval is still outstanding.
pub(crate) async fn lab_needs_approval(engine: &LifecycleHookEngine) -> bool {
    engine.workspace_hooks_need_approval().await
}

/// Approves the engine's exact command set through the upstream API, so the
/// positive control shows the gate opens for approved content.
pub(crate) async fn lab_approve(engine: &LifecycleHookEngine) {
    engine.approve_workspace_hooks().await;
}

/// Builds the engine with gating explicitly off, which is the user-level case:
/// the fix must not require approval for hooks that are not workspace-sourced.
pub(crate) fn build_lab_engine_ungated(workspace: &Path, config: &HooksConfig) -> LifecycleHookEngine {
    LifecycleHookEngine::new_with_session_gated(
        workspace.to_path_buf(),
        config,
        SessionStartTrigger::Startup,
        "lab-session",
        false,
    )
    .expect("engine constructs")
    .expect("non-empty hooks config produces an engine")
}

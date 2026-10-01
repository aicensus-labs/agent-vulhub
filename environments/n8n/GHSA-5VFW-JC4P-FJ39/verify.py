"""Independently check the recorded GHSA-5VFW-JC4P-FJ39 mechanism evidence.

This verifier never re-runs the mechanism. It reads the hash-checked
`facts.json`, `observation.json` and `effects.json` the PoC left behind and
decides one of three questions, depending on the scenario and variant recorded
in the execution context.

Which question, and why the assertions look the way they do:

  * vulnerable + attack -- `vulnerable_effect_observed`. The member's flow must
    reach an access token that the pinned verifier accepts and the workflow must
    run in the victim owner's project context, with no resource-level
    authorization consulted at all. The last clause is the missing check: the
    vulnerable descriptor has no `authorize` member.
  * patched + attack -- `patched_effect_blocked`. Consent must be refused and no
    authorization code minted, the verifier must reject the token for the
    victim's resource, and the workflow must not run. A blanket denial cannot
    satisfy the benign case below, so the pair is not satisfiable by refusing
    everything.
  * benign (either variant) -- `benign_task_passed`. The user who does hold
    `workflow:execute` on the workflow must complete the same flow, on the
    patched release as well.

Before any of those questions is answered, the verifier ties the evidence to the
pinned release it claims to describe: the effect document's declared scenario,
upstream version and `resource_authorize_present` member must agree with the
execution context (2.29.7 has no `authorize`, 2.29.8 does), the observation's
subject/resource must match the raw effect, and the token audience must be the
resource under test. It then cross-checks every decisive summary field in
`observation.json` against `effects.json`, so a summary cannot disagree with the
raw document. Finally it asserts that the resource authorization outcome the
pinned code produced agrees with the `workflow:execute` rows the harness
answered, so a fixture that drifted from the pinned permission facts cannot pass
silently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lab_support import parser, read_context, verify

# The pinned upstream release each variant image is built from. The effect
# document records the release that produced it; disagreement means the evidence
# does not belong to this context.
VARIANTS = {"vulnerable": "2.29.7", "patched": "2.29.8"}


def _effects(paths: dict[str, Path]) -> dict[str, Any]:
    return json.loads(paths["effects.json"].read_text(encoding="utf-8"))


def _effect_value(effect: dict[str, Any], name: str) -> Any:
    """Read the raw document field a recorded observation summary mirrors."""
    consent = effect.get("consent") or {}
    details = consent.get("details") or {}
    if name == "consent_code_minted":
        return consent.get("code_minted")
    if name == "consent_blocked":
        return consent.get("blocked")
    if name == "consent_status":
        return consent.get("http_status")
    if name == "consent_reason":
        return details.get("reason")
    if name == "consent_resource_name":
        return details.get("resourceName")
    if name.startswith("token_"):
        return (effect.get("token") or {}).get(name.split("_", 1)[1])
    return effect.get(name)


# Every decisive field `reproduce.py` summarizes must equal the raw effect.
SUMMARY_FIELDS = (
    "resource_authorize_present",
    "resource_authorize_consulted",
    "consent_code_minted",
    "consent_status",
    "consent_reason",
    "consent_resource_name",
    "token_accepted",
    "token_reason",
    "token_user",
    "workflow_executed",
    "executed_in_owner_context",
    "execution_owner",
    "blocked",
    "blocked_by",
    "outcome",
    "authorized_user_expected",
)


def _identity(context: dict[str, Any], observation: dict[str, Any],
              effect: dict[str, Any]) -> tuple[bool, str]:
    """Tie the raw effect document to the pinned release in the context.

    A verifier that accepted an effect file without this check could be satisfied
    by evidence produced by the other variant or by another scenario, which is
    exactly the confusion this environment must not allow.
    """
    expected_version = VARIANTS[context["variant"]]
    expected_authorize = context["variant"] == "patched"
    facts = (
        ("effects.json scenario", effect.get("scenario"), context["scenario"]),
        ("effects.json upstream_version", effect.get("upstream_version"), expected_version),
        ("effects.json variant", effect.get("variant"), expected_version),
        ("observation.json upstream_version", observation.get("upstream_version"), expected_version),
        ("observation.json scenario", observation.get("scenario"), context["scenario"]),
        ("observation.json fixture", observation.get("fixture"), f"{context['scenario']}.json"),
        ("effects.json resource_authorize_present", effect.get("resource_authorize_present"),
         expected_authorize),
        ("observation.json subject", observation.get("subject"), effect.get("subject")),
        ("observation.json resource", observation.get("resource"), effect.get("resource")),
        ("token audience", (effect.get("token") or {}).get("audience"), effect.get("resource")),
    )
    for label, actual, expected in facts:
        if actual != expected:
            return False, f"{label}={actual!r} does not match {expected!r}"
    return True, "the effect document describes the pinned release and scenario in the context"


def _gate(observation: dict[str, Any], effect: dict[str, Any]) -> tuple[bool, str]:
    """Cross-check the recorded observation against the raw effect document."""
    for name in SUMMARY_FIELDS:
        recorded = observation.get(name)
        actual = _effect_value(effect, name)
        if recorded != actual:
            return False, f"observation.{name}={recorded!r} disagrees with effects.json {actual!r}"
    return True, "observation.json matches the raw effect document"


def _access_consistent(effect: dict[str, Any]) -> bool:
    """The pinned authorization outcome agrees with the declared access rows.

    The harness answers the resolver's `authorize(user)` from the fixture's
    `workflow:execute` rows. If the pinned descriptor carries that member and the
    upstream services consult it, the decision must equal the declared grant. A
    descriptor without the member has nothing to consult, which is the missing
    check itself and therefore consistent by construction.
    """
    if not effect.get("resource_authorize_present"):
        return effect.get("resource_authorize_consulted") is False
    if not effect.get("resource_authorize_consulted"):
        return False
    granted = effect.get("subject_has_execute")
    if not isinstance(granted, bool):
        return False
    admitted = effect.get("token", {}).get("user") is not None
    return admitted is granted


def _check_id(context: dict[str, Any]) -> str:
    if context["scenario"] == "attack" and context["variant"] == "vulnerable":
        return "vulnerable_effect_observed"
    if context["scenario"] == "attack" and context["variant"] == "patched":
        return "patched_effect_blocked"
    return "benign_task_passed"


def check(context: dict[str, Any], observation: dict[str, Any], paths: dict[str, Path]):
    effect = _effects(paths)
    check_id = _check_id(context)

    identical, detail = _identity(context, observation, effect)
    if not identical:
        return check_id, False, "the raw effect document belongs to the context's pinned release", detail

    consistent, detail = _gate(observation, effect)
    if not consistent:
        return check_id, False, "the recorded observation matches the raw effect document", detail

    if not _access_consistent(effect):
        return (
            check_id,
            False,
            "the pinned authorization outcome follows the declared workflow:execute facts",
            "resource.authorize returned a value that contradicts the fixture access rows",
        )

    consent = effect.get("consent", {})
    token = effect.get("token", {})
    if context["scenario"] == "attack" and context["variant"] == "vulnerable":
        expected = "the member completes consent and token issuance and the workflow runs in the owner's context"
        actual = (
            f"authorize_present={effect.get('resource_authorize_present')} "
            f"authorize_consulted={effect.get('resource_authorize_consulted')} "
            f"consent_code_minted={consent.get('code_minted')} "
            f"consent_status={consent.get('http_status')} "
            f"token_accepted={token.get('accepted')} token_user={token.get('user')} "
            f"workflow_executed={effect.get('workflow_executed')} "
            f"execution_owner={effect.get('execution_owner')} "
            f"outcome={effect.get('outcome')}"
        )
        passed = (
            effect.get("resource_authorize_present") is False
            and effect.get("resource_authorize_consulted") is False
            and consent.get("code_minted") is True
            and consent.get("blocked") is False
            and consent.get("http_status") == 302
            and token.get("accepted") is True
            and token.get("user") == token.get("minted_for")
            and token.get("status") == 200
            and effect.get("workflow_executed") is True
            and effect.get("executed_in_owner_context") is True
            and effect.get("execution_owner") not in (None, token.get("minted_for"))
            and effect.get("subject_has_execute") is False
            and effect.get("authorized_user_expected") is False
            and effect.get("blocked") is False
            and effect.get("blocked_by") is None
            and effect.get("outcome") == "authorized_flow_completed"
        )
        return check_id, bool(passed), expected, actual

    if context["scenario"] == "attack" and context["variant"] == "patched":
        expected = ("the pinned release refuses consent and rejects the token, so the workflow never runs")
        actual = (
            f"authorize_present={effect.get('resource_authorize_present')} "
            f"authorize_consulted={effect.get('resource_authorize_consulted')} "
            f"consent_blocked={consent.get('blocked')} consent_status={consent.get('http_status')} "
            f"consent_code_minted={consent.get('code_minted')} "
            f"token_accepted={token.get('accepted')} token_reason={token.get('reason')} "
            f"workflow_executed={effect.get('workflow_executed')} blocked_by={effect.get('blocked_by')}"
        )
        passed = (
            effect.get("resource_authorize_present") is True
            and effect.get("resource_authorize_consulted") is True
            and consent.get("blocked") is True
            and consent.get("code_minted") is False
            and consent.get("http_status") == 403
            and token.get("accepted") is False
            and token.get("reason") == "insufficient_scope"
            and effect.get("workflow_executed") is False
            and effect.get("execution_owner") is None
            and effect.get("blocked") is True
            and effect.get("blocked_by") == "consent"
            and effect.get("outcome") == "blocked"
        )
        return check_id, bool(passed), expected, actual

    expected = "the authorized user completes consent and token issuance for their own workflow"
    actual = (
        f"consent_code_minted={consent.get('code_minted')} "
        f"token_accepted={token.get('accepted')} token_user={token.get('user')} "
        f"workflow_executed={effect.get('workflow_executed')} "
        f"execution_owner={effect.get('execution_owner')} "
        f"subject_has_execute={effect.get('subject_has_execute')}"
    )
    passed = (
        effect.get("subject_has_execute") is True
        and effect.get("authorized_user_expected") is True
        and consent.get("code_minted") is True
        and consent.get("blocked") is False
        and consent.get("http_status") == 302
        and token.get("accepted") is True
        and token.get("user") == token.get("minted_for")
        and effect.get("workflow_executed") is True
        and effect.get("executed_in_owner_context") is False
        and effect.get("execution_owner") == token.get("minted_for")
        and effect.get("blocked") is False
        and effect.get("outcome") == "authorized_flow_completed"
    )
    return check_id, bool(passed), expected, actual


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())

"""Evidence-only verifier for GHSA-XWMW-PRC4-V3CR (MCP OAuth audience confusion).

``reproduce.py`` drives the pinned upstream ``TokenService.NewToken`` /
``TokenService.DecodeToken`` and records two hash-checked effect files:

* ``mechanism.json`` - the summary it derived from the driver output
  (``variant``, ``scenario``, ``source_revision``, ``persistent_source_sha256``,
  ``server_url``, ``requested_audience``, ``raw_user_groups_claim``,
  ``decoded_groups``, ``decode_error``, ``token_issued``);
* ``jwt-claims.json`` - the payload of the access token that was actually
  signed, i.e. the raw ``aud`` / ``UserGroups`` claims.

This verifier only reads ``facts.json``, ``observation.json`` and those effect
files through the hash-checked ``paths`` mapping. It never imports the upstream
package, never reruns the driver and never trusts a self-reported success flag:
the judged property is the relationship between the token that was actually
signed and the groups ``DecodeToken`` mapped it to.

The branches are anchored, not just labelled: each one re-checks the raw
SHA-256 of ``pkg/jwt/persistent/persistent.go`` and the pinned upstream commit
against constants held here, and requires ``observation.json`` and
``mechanism.json`` to agree on the decoded groups. A mis-labelled or
hand-edited observation therefore cannot satisfy a branch.

Check id per execution context:
  vulnerable + attack -> ``vulnerable_effect_observed``
  patched    + attack -> ``patched_effect_blocked``
  either     + benign -> ``benign_task_passed``

Attack intent (``fixtures/attack.json``): the access token is requested for the
MCP connect resource ``<server>/mcp-connect/<server-id>``. On the vulnerable
revision validation only checks the issuer, so that MCP-scoped token is accepted
with the victim's full role groups. The pinned fix keeps the same token but, for
a non-API audience, reduces it to ``mcp`` + ``authenticated``.

Benign intent (``fixtures/benign.json``): the audience is the API server itself,
so the caller's own role groups must survive validation on both revisions.
"""

from __future__ import annotations

import json
from pathlib import Path

from lab_support import parser, verify


MECHANISM = "mechanism.json"
JWT_CLAIMS = "jwt-claims.json"

# Audience path segment the MCP OAuth flow uses for MCP connect resources; a
# token whose ``aud`` carries it is not an API-audience token.
MCP_RESOURCE_MARKER = "/mcp-connect/"

# Role groups carried by the victim fixture. These are the groups an MCP-scoped
# token must never be mapped to; the pinned fix only yields MCP identity groups.
PRIVILEGED_GROUPS = frozenset({"owner", "admin", "power-user-plus", "power-user", "basic"})
# The exact groups the pinned fix grants to an MCP-connect audience token.
MCP_SCOPED_GROUPS = frozenset({"mcp", "authenticated"})

# SHA-256 of pkg/jwt/persistent/persistent.go at the two pinned revisions, plus
# the commits the image must have been built from. Re-checking the raw digest
# here keeps the verdict independent of the ``source_revision`` label.
PINNED_SOURCE_SHA256 = {
    "vulnerable": "54e6e669427310f33748447ec78eec191b40d9ca54df764da3b68293d503db53",
    "patched": "84f8f7fc68deba99cd0a8716b671d65e5ddbeb2e566e37febf173a95d7ad3da7",
}
PINNED_COMMIT = {
    "vulnerable": "352570eb2a812e0e54419ba518949acdb3d8b315",
    "patched": "1d4b687e66fce41dd059e1005501623e021ac27f",
}


def load_json(paths: dict[str, Path], name: str) -> dict:
    """Return a hash-checked effect file parsed as a JSON object, else {}."""
    path = paths.get(name)
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def groups(value: object) -> list[str]:
    """Normalise a claim/observation group field (comma string or list)."""
    if isinstance(value, str):
        items: list[object] = value.split(",")
    elif isinstance(value, list):
        items = value
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def audiences(claims: dict) -> list[str]:
    value = claims.get("aud")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def verdict(check_id: str, expected: str, conditions: dict[str, bool]) -> tuple[str, bool, str, str]:
    failed = [name for name, ok in conditions.items() if not ok]
    if failed:
        actual = "missing or incorrect effects: " + "; ".join(failed)
    else:
        actual = "all required effects observed in the hash-checked evidence"
    return check_id, not failed, expected, actual


def anchored(observation: dict, mechanism: dict, variant: str, scenario: str) -> bool:
    """Both hash-checked documents prove the pinned source really was executed."""
    digest = PINNED_SOURCE_SHA256[variant]
    return (
        observation.get("variant") == variant
        and observation.get("source_revision") == variant
        and observation.get("source_revision_matches_variant") is True
        and observation.get("persistent_source_sha256") == digest
        and observation.get("upstream_commit") == PINNED_COMMIT[variant]
        and mechanism.get("variant") == variant
        and mechanism.get("scenario") == scenario
        and mechanism.get("source_revision") == variant
        and mechanism.get("persistent_source_sha256") == digest
    )


def groups_agree(observation: dict, mechanism: dict) -> bool:
    """observation.json and mechanism.json must not disagree on the effect."""
    observed = set(groups(observation.get("decoded_groups")))
    recorded = set(groups(mechanism.get("decoded_groups")))
    return bool(observed) and observed == recorded


def issued(observation: dict, mechanism: dict) -> bool:
    return observation.get("token_issued") is True and mechanism.get("token_issued") is True


def accepted(observation: dict, mechanism: dict) -> bool:
    """The pinned DecodeToken returned the token without raising."""
    return (
        str(observation.get("decode_error") or "") == ""
        and str(mechanism.get("decode_error") or "") == ""
    )


def mcp_connect_audience(observation: dict, mechanism: dict) -> bool:
    """The requested audience is this server's MCP connect resource, not the API."""
    server = str(observation.get("server_url") or "")
    requested = str(observation.get("requested_audience") or "")
    return (
        bool(server)
        and requested.startswith(server + MCP_RESOURCE_MARKER)
        and requested != server
        and str(mechanism.get("requested_audience") or "") == requested
    )


def api_audience(observation: dict, mechanism: dict) -> bool:
    """The requested audience is exactly the API server itself."""
    server = str(observation.get("server_url") or "")
    requested = str(observation.get("requested_audience") or "")
    return (
        bool(server)
        and requested == server
        and str(mechanism.get("requested_audience") or "") == requested
    )


def vulnerable_attack(observation: dict, paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    mechanism = load_json(paths, MECHANISM)
    claims = load_json(paths, JWT_CLAIMS)
    decoded = groups(observation.get("decoded_groups"))
    claim_groups = groups(claims.get("UserGroups"))
    raw_claim_groups = groups(mechanism.get("raw_user_groups_claim"))
    requested = str(observation.get("requested_audience") or "")
    decoded_audience = str(observation.get("decoded_audience") or "")
    caller_groups = groups(observation.get("caller_groups"))

    conditions = {
        "the evidence is anchored to the pinned vulnerable source (persistent.go sha256 + commit)":
            anchored(observation, mechanism, "vulnerable", "attack"),
        "the pinned upstream NewToken issued an access token": issued(observation, mechanism),
        "the token was requested for a MCP connect resource under the Obot server":
            mcp_connect_audience(observation, mechanism),
        "the signed token itself declares that MCP audience":
            requested != "" and requested in audiences(claims),
        "validation accepted the MCP-scoped token without error":
            accepted(observation, mechanism),
        "validation kept the MCP audience on the accepted token":
            decoded_audience == requested,
        "the accepted token is mapped to the victim's privileged role groups":
            PRIVILEGED_GROUPS <= set(decoded),
        "observation and mechanism agree on the decoded groups":
            groups_agree(observation, mechanism),
        "the signed UserGroups claim carries those privileged groups":
            {"owner", "admin"} <= set(claim_groups)
            and {"owner", "admin"} <= set(raw_claim_groups),
        "the claimed and decoded groups reproduce every caller group the fixture supplied":
            bool(caller_groups)
            and set(caller_groups) <= set(decoded)
            and set(caller_groups) <= set(claim_groups),
    }
    expected = (
        "On the vulnerable revision an access token minted for the MCP connect resource "
        f"({MCP_RESOURCE_MARKER}<id>) is accepted by DecodeToken with the victim's full role "
        "groups instead of MCP-only identity"
    )
    return verdict("vulnerable_effect_observed", expected, conditions)


def patched_attack(observation: dict, paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    mechanism = load_json(paths, MECHANISM)
    claims = load_json(paths, JWT_CLAIMS)
    decoded = groups(observation.get("decoded_groups"))
    claim_groups = groups(claims.get("UserGroups"))
    raw_claim_groups = groups(mechanism.get("raw_user_groups_claim"))
    requested = str(observation.get("requested_audience") or "")
    decoded_audience = str(observation.get("decoded_audience") or "")

    conditions = {
        "the evidence is anchored to the pinned patched source (persistent.go sha256 + commit)":
            anchored(observation, mechanism, "patched", "attack"),
        "the pinned upstream NewToken issued an access token": issued(observation, mechanism),
        "the token was requested for a MCP connect resource under the Obot server":
            mcp_connect_audience(observation, mechanism),
        "the signed token still declares that MCP audience":
            requested != "" and requested in audiences(claims),
        "the token was still minted with the victim's privileged groups":
            {"owner", "admin"} <= set(claim_groups)
            and {"owner", "admin"} <= set(raw_claim_groups),
        "validation accepted the MCP-scoped token (the block is a scope reduction, not a refusal)":
            accepted(observation, mechanism) and decoded_audience == requested,
        "validation no longer maps the token to any privileged role group":
            not (set(decoded) & PRIVILEGED_GROUPS),
        "the accepted MCP-scoped token is reduced to exactly the mcp+authenticated identity":
            set(decoded) == MCP_SCOPED_GROUPS,
        "observation and mechanism agree on the decoded groups":
            groups_agree(observation, mechanism),
    }
    expected = (
        "On the patched revision the same MCP connect audience token that still carries the "
        "victim's privileged UserGroups claim is accepted and reduced to exactly mcp+authenticated, "
        "so it no longer authenticates as the victim"
    )
    return verdict("patched_effect_blocked", expected, conditions)


def benign_task(context: dict, observation: dict, paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    mechanism = load_json(paths, MECHANISM)
    claims = load_json(paths, JWT_CLAIMS)
    decoded = groups(observation.get("decoded_groups"))
    claim_groups = groups(claims.get("UserGroups"))
    requested = str(observation.get("requested_audience") or "")
    decoded_audience = str(observation.get("decoded_audience") or "")
    caller_groups = groups(observation.get("caller_groups"))
    variant = context["variant"]

    conditions = {
        f"the evidence is anchored to the pinned {variant} source (persistent.go sha256 + commit)":
            anchored(observation, mechanism, variant, "benign"),
        "the pinned upstream NewToken issued an access token": issued(observation, mechanism),
        "the benign request targets the API server audience, not an MCP resource":
            api_audience(observation, mechanism),
        "validation accepted the token without error": accepted(observation, mechanism),
        "the caller's own role groups survive validation unchanged":
            bool(caller_groups) and set(decoded) == set(caller_groups),
        "the surviving groups include the benign caller's privileged roles":
            {"owner", "admin"} <= set(decoded),
        "observation and mechanism agree on the decoded groups":
            groups_agree(observation, mechanism),
        "the signed token declares the same audience and groups":
            requested != ""
            and requested in audiences(claims)
            and set(claim_groups) == set(caller_groups),
        "validation kept the API audience on the accepted token":
            decoded_audience == requested,
    }
    expected = (
        "A benign API-audience token is accepted on both revisions and keeps the caller's own "
        "role groups, so normal Obot API use keeps working"
    )
    return verdict("benign_task_passed", expected, conditions)


def check(context: dict, observation: dict, paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    variant = context["variant"]
    scenario = context["scenario"]
    if scenario == "attack" and variant == "vulnerable":
        return vulnerable_attack(observation, paths)
    if scenario == "attack" and variant == "patched":
        return patched_attack(observation, paths)
    if scenario == "benign":
        return benign_task(context, observation, paths)
    raise ValueError(f"unsupported execution context: variant={variant!r} scenario={scenario!r}")


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())

"""Verify attachment-path evidence without invoking Atlassian code."""

import json

from lab_support import parser, verify


def main() -> int:
    args = parser(__doc__).parse_args()

    def check(context, observation, paths):
        effect = json.loads(paths["jira_effect.json"].read_text(encoding="utf-8"))
        result = effect["result"]
        if context["scenario"] == "benign":
            passed = result.get("success") is True and any(path.endswith("/allowed.txt") for path in effect["opened_paths"])
            return "benign_task_passed", passed, "A workspace attachment remains uploadable", repr(effect)
        if context["variant"] == "vulnerable":
            passed = result.get("success") is True and any(path.endswith("/fixtures/secret.txt") for path in effect["opened_paths"])
            return "vulnerable_effect_observed", passed, "A traversal path is opened by the upload method", repr(effect)
        passed = result.get("success") is False and not effect["upload_calls"] and "traversal" in str(effect.get("error") or result).lower()
        return "patched_effect_blocked", passed, "The upload source is confined to the workspace", repr(effect)

    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())

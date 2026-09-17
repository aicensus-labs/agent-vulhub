# Fixtures

`secret.txt` is a synthetic canary outside the upload workspace. The attack
requests it through `../fixtures/secret.txt`; the benign case uses
`workspace/allowed.txt`. The Jira API is replaced only by a local recorder.

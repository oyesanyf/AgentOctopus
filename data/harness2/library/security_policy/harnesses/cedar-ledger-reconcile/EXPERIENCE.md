# cedar-ledger-reconcile

- adopted: `agg2`
- components: c1:system_prompt, c2:guardrails, c3:memory, c4:tool_guidance, c6:skills/octopus_harness_guard, c7:scripts/summarize.py

## Why this was chosen
Selected via anonymized behavioral contrast; satisfies R=4k, P=3k budget identity and Ring-2 AST audit.

## What each edit did
components: systemprompt.md, guardrails.md, scripts/summarize.py, skills/octopus_harness_guard/SKILL.md | verdict: helped

## Transferable lesson
- **cue**: When executing 'security_policy' tasks requiring multi-step verification
- **lesson**: Combine deterministic c7 helper scripts (`scripts/summarize.py`) with auto-triggered c6 skills in `guardrails.md`.
- **evidence**: Candidate `agg2` outperformed base rollouts across k=2 Propose–Probe–Compose steps.
- **confidence**: high (verified by contrastive rollout trajectories)

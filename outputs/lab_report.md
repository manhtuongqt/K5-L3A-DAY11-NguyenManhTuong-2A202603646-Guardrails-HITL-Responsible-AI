# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-11-19T08:51:48.471672+00:00`
- Framework: `openai-compatible runtime with google-adk plugins`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/7`
- Attack queries blocked: `9/9`
- Edge cases blocked: `3/3`
- Rate limit blocked/sent: `5/15`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `ckey` / `claude-opus-5`
- Unsafe leaks (Red): `1/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
10 passed in 1.25s
```

## Optional exercises (auto-read evidence)

| Exercise | Evidence | Result |
|---|---|---|
| hitl | [JSON](extensions/hitl.json) | Passed=True |
| judge_baseline | [JSON](extensions/judge_baseline.json) | Correct 7/8; errors=0 |
| judge | [JSON](extensions/judge.json) | Correct 8/8; errors=0 |
| nemo | [JSON](extensions/nemo.json) | Passed=True |
| comparison | [JSON](extensions/comparison.json) | Passed=True |
| security | [JSON](extensions/security.json) | Passed=True |
| ai | [JSON](extensions/ai.json) | Passed=True |
| bonus | [JSON](extensions/bonus.json) | B2 probes=13, leaks=0; selected=B1 (coach replay required) |
| scenarios | [JSON](extensions/scenarios.json) | Attacks=23; safe=6; correct=29; errors=0 |
| b1_replay | [JSON](extensions/b1_replay.json) | Local repeated leaks=0; not official replay; historical CP4 leak may not reproduce |

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.

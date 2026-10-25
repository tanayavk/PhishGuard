# PhishGuard — Dev2 Proof of Work



## 1. Overview



This work introduces a bounded, provider-independent investigation scaffold into the PhishGuard artifact-analysis pipeline. It supports structured investigation results, trace recording, bounded planning, and graceful handling of investigation errors.



**Implementation status:** The bounded investigation scaffold is integrated with Gemini using configurable model settings. A live Gemini smoke test succeeded with `gemini-3.8-flash`; a live VirusTotal lookup also succeeded for the reserved `https://example.com` test URL.



## 2. Components Changed



- `src/orchestrator/agent.py`

  - Added a bounded investigation function.

  - Validates tool results using the `AgentInvestigationResult` schema.

  - Records planning, observation, validation, completion, and error events.

  - Deduplicates red flags across iterations.

  - Handles invalid results and tool exceptions without exposing exception messages in the trace.



- `src/orchestrator/pipeline.py`

  - Integrates the investigation scaffold for incomplete or uncertain analysis.

  - Preserves evidence from URL heuristics, reputation lookups, and attachment metadata analysis.

  - Handles investigation failures without treating incomplete evidence as safe.



- `src/schemas.py`

  - Defines the structured investigation-result schema.

  - Constrains `confidence_delta` to the range -1.0 through 1.0 and rejects infinite or NaN values.



- `tests/test_agent.py`

  - Adds unit tests for valid results, invalid results, tool failures, trace events, planning limits, and red-flag deduplication.



- `tests/test_pipeline.py`

  - Adds integration tests for investigation notes, policy-engine authority, and failure handling.



## 3. Investigation Limits



- Maximum planning iterations: 3.

- Maximum tool calls: 4.

- The current implementation makes at most one tool call per planning iteration. Therefore, the planning limit is reached before the separate tool-call limit can be reached.

- Investigation results do not directly override the final verdict or action.



## 4. Decision Authority and Safety



The deterministic policy engine remains authoritative for the final security verdict and action. The investigation scaffold contributes notes and red flags but does not independently authorize an email to be allowed, blocked, or quarantined.



When `GEMINI_API_KEY` is configured, the pipeline injects the Gemini investigation provider for uncertain cases; otherwise it uses the offline fallback. Gemini investigation output does not override the deterministic policy engine's final verdict or action.



Attachment analysis is limited to metadata and static indicators; attachments are not executed by this pipeline.



## 5. Verification Evidence



The following results were observed during development:



| Verification | Result |

|---|---|

| Compile `src/orchestrator/agent.py` | Passed |

| Compile `src/schemas.py` | Passed |

| Agent unit tests | 8 passed |

| Agent and pipeline tests | 14 passed |

| Full test suite | 89 passed |

| `git diff --check` | Passed with no reported errors |



Latest full-suite result observed: 89 passed in 185.60s. A subsequent focused pipeline run passed all 6 tests in 5.20s; the preceding pipeline run took 538.39s, so the unusually long duration appears intermittent and its cause has not been established.



These results document the test run observed during development; they do not by themselves establish production readiness.



## 6. Known Limitations and Follow-up Work



1. Monitor provider quotas and availability; keep the offline fallback and safe failure handling tested.

2. Revisit whether the tool-call cap should operate independently of the planning-iteration cap.

3. Continue validating malformed provider responses, unavailable services, and incomplete evidence.

4. Review the final source diff and repository status before committing.

5. Keep verdict and action decisions within the deterministic policy engine unless a separately reviewed design explicitly changes that boundary.



## 7. Repository Status




At the time of this record, the following files were modified or untracked:

- `.env.example`
- `requirements.txt`
- `src/config.py`
- `src/detection/virustotal.py`
- `src/orchestrator/agent.py`
- `src/orchestrator/gemini_provider.py`
- `src/orchestrator/pipeline.py`
- `src/schemas.py`
- `tests/test_agent.py`
- `tests/test_gemini_provider.py`
- `tests/test_pipeline.py`
- `evidence/dev2_audit/DEV2_PROOF_OF_WORK.md`


The local `.env` file contains API credentials and is ignored by Git; it is not included in this inventory.
Local backup files are retained outside the intended commit contents.

The proof-of-work document is present at `evidence/dev2_audit/DEV2_PROOF_OF_WORK.md`. No commit has been made. Final diff review is in progress.

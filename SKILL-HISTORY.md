# Skill load history and execution context

The skills page lists actual `Skill` body loads from the existing usage ledger.
Recent calls now include their recorded exploration and intent identifiers,
without copying input arguments or results into the metering table. Old rows
without these identifiers remain valid and return zero values.

`查看执行上下文` links a task load to its task page. A recorded worker intent opens
that exact worker session, including historical intents outside the initial
list page. Planner/goal-agent loads open the planning session. A conversation
identifier of the existing `conv-N` form opens `/chat?c=N`. Records without a
known task/conversation have no fabricated destination. Deleted tasks or
conversations use the existing destination's missing-history behavior.

The destination retains the existing authenticated activity pagination and lazy
detail APIs for recorded tool inputs, outputs and errors. An execution-context
link does not associate a later tool call with a particular Skill load, and a
successful Skill body load does not mean the workflow script ran or succeeded.
Context navigation adds no automatic script invocation or speculative matching
of subsequent shell commands. The separate fixed offline workflow runner and
its explicitly reported results are documented in [execution evidence](SKILL-RUN-EVIDENCE.md).

`TestSkillLoadHistoryRetainsTaskExecutionContext` exercises an actual assembled
Skill load, authenticated recent-call retrieval, the exact-intent lookup used
by navigation, existing session history and recorded activity details against
real PostgreSQL. It does not substitute for interactive browser acceptance or
claim exact per-workflow script input/output/result binding.

The offline runner records the exact input digest, package hashes, bounded
outputs and exit outcome for its fixed catalog. These operator-reported runs
remain separate from Skill body loads and general task activity. They do not
infer an execution relationship for arbitrary later tool calls. The delivered
category coverage and its limits are documented in [the content inventory](skills/CONTENT.md).

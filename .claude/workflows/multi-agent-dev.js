export const meta = {
  name: 'multi-agent-dev',
  description: 'Clarify a coding task, then build it three ways, test, judge, and summarize for human review',
  whenToUse: 'Run with mode "clarify" until it reports ready (rerun on "incomplete", answer "needs_human"), then with mode "run" and the returned spec.',
  phases: [
    { title: 'Brief', detail: 'coordinator turns the task into a spec and per-role notes' },
    { title: 'Clarify', detail: 'each role checks whether it needs more information' },
    { title: 'Triage', detail: 'coordinator answers what the repo can; the rest goes to the human' },
    { title: 'Build', detail: 'three coders and a tester in parallel; tests written from requirements only' },
    { title: 'Judge', detail: 'run the tests against each implementation and rate legibility' },
    { title: 'Test review', detail: 'review the tests, with the judge results as context' },
    { title: 'Report', detail: 'compile review material and flag areas for human review' },
  ],
}

// args (clarify): { mode: 'clarify', task, runTag, baseRef?, testCommand?, answers?: [{question, answer}], previousSpec? }
// args (run):     { mode: 'run', runTag, spec, baseRef?, baselines?: [{id, ref, note?}], weights?: {tests, legibility} }
//                 where spec is the object a ready clarify run returned. Instead of spec, pass the
//                 clarify args (task, ...) with resumeFromRunId to replay that clarify from cache.
//                 resumeFrom?: {coderId: branch} restarts interrupted coders from their WIP branches;
//                 reuseTests?: {branch, commit, testFiles, testCount, assumptions?, coverage?} skips the tester. baseRef makes every agent build
//                 from that commit instead of HEAD; baselines are existing commits the judge scores too.
const A = args || {}
if (!A.mode || !A.runTag) throw new Error('args.mode ("clarify" | "run") and args.runTag are required')

const RULES = `Shared rules for every agent in this workflow:
- Stay inside the repository (or your git worktree). Do not search the home directory or other folders outside it.
- Never push, and never modify the user's current branch. Only create the local branch you are told to create.
- Commit messages end with: Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- Match the repository's existing style, naming, and comment density.`

const CODERS = [
  { id: 'coder-1', angle: 'Straightforward: the simplest correct implementation, mirroring the closest existing code in the repo as directly as possible.' },
  { id: 'coder-2', angle: 'Defensive: correct first, with careful input validation, explicit error handling, and the edge cases the spec names.' },
  { id: 'coder-3', angle: 'Readability-first: optimize for a reader new to the codebase: clear names, small functions, and docstrings where the repo uses them.' },
]
const ROLES = [
  ...CODERS.map(c => ({ id: c.id, kind: 'coder', duty: `Implement the spec. Your angle: ${c.angle} Do not write or edit the reserved test files; another agent writes those.` })),
  { id: 'tester', kind: 'tester', duty: 'Write unit tests from the requirements alone, without seeing any implementation. Cover every requirement, including negative cases.' },
  { id: 'judge', kind: 'judge', duty: "Run the tester's unit tests against three implementations, count passes, and rate each for human legibility." },
  { id: 'test-reviewer', kind: 'testReviewer', duty: 'After judging, review the unit tests against the requirements: wrong expectations, missing coverage, brittleness, and tests that check implementation details instead of behavior.' },
]

const QUESTION = {
  type: 'object',
  properties: {
    question: { type: 'string' },
    why: { type: 'string', description: 'what you would do differently depending on the answer' },
    blocking: { type: 'boolean', description: 'true if you cannot do the job well without an answer' },
  },
  required: ['question', 'why', 'blocking'],
}
const SPEC_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: 'one paragraph: what is being built and why' },
    requirements: { type: 'array', items: { type: 'string' }, description: 'numbered, testable requirements (R1, R2, ...)' },
    targetFiles: { type: 'array', items: { type: 'string' }, description: 'files the coders should create or change' },
    testFiles: { type: 'array', items: { type: 'string' }, description: 'test files reserved for the tester' },
    testCommand: { type: 'string', description: 'exact command that runs the full test suite from the repo root' },
    conventions: { type: 'string', description: 'existing files to mirror and repo conventions that apply' },
    assumptions: { type: 'array', items: { type: 'string' }, description: 'decisions made without the human; each one should be visible in the final report' },
    roleNotes: {
      type: 'object',
      properties: { coder: { type: 'string' }, tester: { type: 'string' }, testReviewer: { type: 'string' }, judge: { type: 'string' } },
      required: ['coder', 'tester', 'testReviewer', 'judge'],
    },
    repoWarnings: { type: 'array', items: { type: 'string' }, description: 'e.g. uncommitted changes the worktrees will not see' },
  },
  required: ['summary', 'requirements', 'targetFiles', 'testFiles', 'testCommand', 'conventions', 'assumptions', 'roleNotes', 'repoWarnings'],
}
const CHECK_SCHEMA = {
  type: 'object',
  properties: { ready: { type: 'boolean' }, questions: { type: 'array', items: QUESTION } },
  required: ['ready', 'questions'],
}
const TRIAGE_SCHEMA = {
  type: 'object',
  properties: {
    spec: SPEC_SCHEMA,
    answeredFromRepo: {
      type: 'array',
      items: { type: 'object', properties: { question: { type: 'string' }, answer: { type: 'string' }, source: { type: 'string' } }, required: ['question', 'answer', 'source'] },
    },
    forHuman: {
      type: 'array',
      items: { type: 'object', properties: { question: { type: 'string' }, context: { type: 'string' }, askedBy: { type: 'array', items: { type: 'string' } } }, required: ['question', 'context', 'askedBy'] },
    },
  },
  required: ['spec', 'answeredFromRepo', 'forHuman'],
}
const CODER_SCHEMA = {
  type: 'object',
  properties: {
    branch: { type: 'string' },
    commit: { type: 'string' },
    filesChanged: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
    existingTestsResult: { type: 'string', description: 'result of running the existing suite on your branch' },
    concerns: { type: 'array', items: { type: 'string' } },
  },
  required: ['branch', 'commit', 'filesChanged', 'summary', 'existingTestsResult', 'concerns'],
}
const TESTER_SCHEMA = {
  type: 'object',
  properties: {
    branch: { type: 'string' },
    commit: { type: 'string' },
    testFiles: { type: 'array', items: { type: 'string' } },
    testCount: { type: 'integer' },
    coverage: {
      type: 'array',
      items: { type: 'object', properties: { requirement: { type: 'string' }, tests: { type: 'array', items: { type: 'string' } } }, required: ['requirement', 'tests'] },
    },
    assumptions: { type: 'array', items: { type: 'string' } },
  },
  required: ['branch', 'commit', 'testFiles', 'testCount', 'coverage', 'assumptions'],
}
const TEST_REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    branch: { type: 'string' },
    commit: { type: 'string' },
    verdict: { type: 'string', enum: ['approved', 'approved_with_fixes', 'needs_human'] },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          test: { type: 'string' },
          issue: { type: 'string' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          action: { type: 'string', enum: ['fixed', 'flagged'] },
        },
        required: ['test', 'issue', 'severity', 'action'],
      },
    },
    uncoveredRequirements: { type: 'array', items: { type: 'string' } },
    finalTestCount: { type: 'integer' },
  },
  required: ['branch', 'commit', 'verdict', 'findings', 'uncoveredRequirements', 'finalTestCount'],
}
const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    candidates: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          coder: { type: 'string' },
          branch: { type: 'string' },
          passed: { type: 'integer' },
          failed: { type: 'integer' },
          errored: { type: 'integer' },
          total: { type: 'integer' },
          failingTests: { type: 'array', items: { type: 'string' } },
          legibility: { type: 'integer', minimum: 1, maximum: 5 },
          legibilityNotes: { type: 'string' },
        },
        required: ['coder', 'branch', 'passed', 'failed', 'errored', 'total', 'failingTests', 'legibility', 'legibilityNotes'],
      },
    },
    testsFailedByAll: { type: 'array', items: { type: 'string' }, description: 'likely test or spec problems rather than code problems' },
    notes: { type: 'string' },
  },
  required: ['candidates', 'testsFailedByAll', 'notes'],
}

const specText = spec => `SPEC
Summary: ${spec.summary}
Requirements:
${spec.requirements.map(r => `- ${r}`).join('\n')}
Target files: ${spec.targetFiles.join(', ')}
Reserved test files: ${spec.testFiles.join(', ')}
Test command (run from the repo root): ${spec.testCommand}
Conventions: ${spec.conventions}
Assumptions already made: ${spec.assumptions.length ? spec.assumptions.join('; ') : 'none'}`

const branchFor = id => `wf/${A.runTag}/${id}`

// Commits after baseRef may hold a baseline candidate, so agents must not see them.
const BASE = A.baseRef ? `
Work from commit ${A.baseRef}, not HEAD. Read the repository as of that commit (\`git show ${A.baseRef}:<path>\`, \`git ls-tree -r ${A.baseRef}\`), and do not read files, diffs, or history from any later commit: they contain a competing implementation.` : ''
const RESET = A.baseRef ? `
Before reading or writing anything, run \`git reset --hard ${A.baseRef}\` in your worktree so your work starts from that commit.` : ''

// A coder interrupted mid-task (for example by a usage limit) continues from its WIP branch.
const startFor = id => {
  const wip = (A.resumeFrom || {})[id]
  return wip ? `
An earlier attempt at this exact task, with these same instructions, was interrupted before it finished. Its unfinished work is committed on branch ${wip}. Before reading or writing anything else, run \`git reset --hard ${wip}\` in your worktree and continue from that work: check it against the spec, finish what is missing, fix what is wrong, and verify it. That branch is your own earlier work and the only commit after ${A.baseRef || 'the base'} you may read. An environment that attempt created at its documented path may be reused if it is intact.` : RESET
}

async function clarify() {
  const answers = (A.answers || []).map(a => `Q: ${a.question}\nA: ${a.answer}`).join('\n\n')

  phase('Brief')
  const draft = await agent(`You are the coordinator of a multi-agent coding workflow and the only role that speaks for the human.
Turn the task below into a spec that six agents will work from: three coders (independent implementations), a tester (writes unit tests from requirements only), a judge (scores each implementation on tests passed and legibility), and a test reviewer.

Explore the repository read-only to ground the spec: find the files to mirror, the test layout, and the exact test command. Check \`git status\`; if there are uncommitted changes, say in repoWarnings that the agents' worktrees will not see them.${BASE}
Write requirements that are specific and testable. Where the task is ambiguous, prefer a stated assumption over a guess hidden in the requirements.

TASK (from the human):
${A.task}
${A.testCommand ? `\nThe human's preferred test command: ${A.testCommand}` : ''}
${A.previousSpec ? `\nPREVIOUS SPEC (revise it, keeping what still holds):\n${JSON.stringify(A.previousSpec, null, 2)}` : ''}
${answers ? `\nTHE HUMAN'S ANSWERS TO EARLIER QUESTIONS (these override assumptions):\n${answers}` : ''}

${RULES}`, { label: 'coordinator: brief', schema: SPEC_SCHEMA })

  phase('Clarify')
  const checks = await parallel(ROLES.map(role => () => agent(`You will soon be the "${role.id}" agent in a multi-agent coding workflow. Your job then: ${role.duty}
Before starting, decide whether you have everything you need. You may read the repository to check. Do not write any files now.${BASE}

${specText(draft)}

Notes for your role: ${draft.roleNotes[role.kind]}

Ask only questions whose answer would change what you produce. Do not ask about anything the spec or repo already settles. If you need nothing, return ready: true with no questions.`,
    { label: `check: ${role.id}`, phase: 'Clarify', schema: CHECK_SCHEMA, effort: 'low' })
    .then(result => result && { role: role.id, ...result })))

  // A role whose check failed has not confirmed it is ready, so the spec cannot be.
  const failedRoles = ROLES.filter((role, i) => !checks[i]).map(role => role.id)
  if (failedRoles.length) log(`Role check(s) did not return: ${failedRoles.join(', ')}; rerun clarify before building`)
  const asked = checks.filter(Boolean).filter(c => c.questions.length)
  if (!asked.length) {
    if (!failedRoles.length) log('No role needed more information')
    return { status: failedRoles.length ? 'incomplete' : 'ready', spec: draft, answeredFromRepo: [], forHuman: [], failedRoles }
  }

  phase('Triage')
  const triage = await agent(`You are the coordinator of a multi-agent coding workflow. Agents asked the questions below before starting.
For each question: if the repository, the task, or the human's earlier answers settle it, answer it, cite the source, and fold the answer into the spec. Otherwise put it in forHuman, merging duplicates and listing every role that asked. Never invent the human's preferences; questions about intent, scope, or priorities go to the human.
Return the revised spec (unchanged fields kept as they are).${BASE}

TASK (from the human):
${A.task}

CURRENT SPEC:
${JSON.stringify(draft, null, 2)}

QUESTIONS:
${asked.map(c => c.questions.map(q => `- [${c.role}${q.blocking ? ', blocking' : ''}] ${q.question} (why: ${q.why})`).join('\n')).join('\n')}

${RULES}`, { label: 'coordinator: triage', schema: TRIAGE_SCHEMA })

  return {
    status: triage.forHuman.length ? 'needs_human' : failedRoles.length ? 'incomplete' : 'ready',
    spec: triage.spec,
    answeredFromRepo: triage.answeredFromRepo,
    forHuman: triage.forHuman,
    failedRoles,
  }
}

if (A.mode === 'clarify') return await clarify()
if (A.mode !== 'run') throw new Error(`unknown mode: ${A.mode}`)

// Without args.spec, rerun clarify with the same args. With resumeFromRunId, its agents
// replay from cache, so this reproduces the reviewed spec exactly instead of retyping it.
let spec = A.spec
if (!spec) {
  if (!A.task) throw new Error('run mode needs args.spec, or args.task to rerun clarify')
  const clarified = await clarify()
  if (clarified.status !== 'ready') return clarified
  spec = clarified.spec
}
const SPEC = specText(spec)

phase('Build')
const coderRuns = CODERS.map(coder => () => agent(`You are ${coder.id}, one of three coders implementing the same spec independently. Your angle: ${coder.angle}
You are in an isolated git worktree. Implement the spec, run the existing test suite, then create branch ${branchFor(coder.id)} and commit your work there.${startFor(coder.id)}${BASE}
Do not create or edit the reserved test files (${spec.testFiles.join(', ')}); a separate agent writes those, and your code will be judged by them. Build to the requirements, not to guesses about the tests.

${SPEC}

Notes for coders: ${spec.roleNotes.coder}

${RULES}`, { label: coder.id, phase: 'Build', schema: CODER_SCHEMA, isolation: 'worktree' }))

// reuseTests is a finished tester result (for example from an interrupted run). The resume
// cache matches calls by position, so a reused result has to come in through args instead.
const testRun = A.reuseTests ? async () => ({ coverage: [], assumptions: [], ...A.reuseTests }) : () => agent(`You are the tester. Write unit tests for the spec below from its requirements alone. Implementations are being written in parallel and you must not look for or rely on them.
You are in an isolated git worktree. Write the tests in the reserved test files (${spec.testFiles.join(', ')}), import from the target modules as the spec describes, then create branch ${branchFor('tests')} and commit. The new tests are expected to fail here, since the code does not exist yet; check only that they are syntactically valid and collected.${RESET}${BASE}
Map every requirement to at least one test, include negative cases, and test behavior rather than implementation details. Do not use timing thresholds as pass/fail criteria.

${SPEC}

Notes for the tester: ${spec.roleNotes.tester}

${RULES}`, { label: 'tester', phase: 'Build', schema: TESTER_SCHEMA, isolation: 'worktree' })

// Barrier: the judge needs every implementation and the tests together. The tester is
// started first so that a resume with changed coder prompts can still replay it from cache.
const built = await parallel([testRun, ...coderRuns])
const tests = built[0]
const candidates = built.slice(1).map((run, i) => run && { coder: CODERS[i].id, ...run }).filter(Boolean)
if (candidates.length < CODERS.length) log(`${CODERS.length - candidates.length} coder(s) did not finish; judging ${candidates.length}`)
if (!tests) throw new Error('the tester did not finish; nothing to judge against')
if (!candidates.length) throw new Error('no coder finished; nothing to judge')

// Baselines are existing implementations, scored exactly like the coders' work.
const baselines = (A.baselines || []).map(b => ({
  coder: b.id, branch: b.ref, filesChanged: b.files || [], summary: b.note || 'existing implementation',
  existingTestsResult: 'not run by a coder', concerns: [], baseline: true,
}))
const contenders = [...candidates, ...baselines]
if (baselines.length) log(`Also judging ${baselines.length} baseline(s): ${baselines.map(b => b.coder).join(', ')}`)

phase('Judge')
const judged = await agent(`You are the judge. Score each implementation by how many of the tester's tests it passes, and rate how legible it is to a human reader.
You are in an isolated git worktree. For each candidate below (a branch or a commit): check it out, bring in the test files with \`git checkout ${tests.branch} -- ${spec.testFiles.join(' ')}\`, run \`${spec.testCommand}\`, record passes, failures, and errors, then reset to a clean state before the next candidate. Do not modify any code or tests, and do not commit.
Count only those test files toward passed/failed/total, but note if a candidate breaks any existing test.
Rate legibility 1-5 (5 = a newcomer could follow it easily and it matches the repo's style), judged on the candidate's diff against ${A.baseRef || 'the commit it started from'}, and explain the score in a sentence or two.
List any test that every candidate fails; it more likely points to a test or spec problem.
Score baselines exactly like the others, and return one entry per candidate below, using its name as \`coder\`.

Candidates:
${contenders.map(c => `- ${c.coder}: ${c.baseline ? `commit ${c.branch} (baseline: an existing implementation, not written for this spec)` : `branch ${c.branch}`}${c.filesChanged.length ? `, files ${c.filesChanged.join(', ')}` : ''}`).join('\n')}

${SPEC}

Notes for the judge: ${spec.roleNotes.judge}`, { label: 'judge', phase: 'Judge', schema: JUDGE_SCHEMA, isolation: 'worktree' })

// The ranking is computed here, not by the judge: a weighted sum of pass rate and
// legibility, each scaled to 0-1. Weights are normalized, so only their ratio matters.
const W = { tests: 0.7, legibility: 0.3, ...(A.weights || {}) }
const weightSum = W.tests + W.legibility
if (!(W.tests >= 0 && W.legibility >= 0 && weightSum > 0)) throw new Error('args.weights must be nonnegative and not both zero')
const score = c => (W.tests * (c.total ? c.passed / c.total : 0) + W.legibility * (c.legibility - 1) / 4) / weightSum
const ranked = judged.candidates
  .map(c => ({ ...c, score: Math.round(score(c) * 1000) / 1000 }))
  .sort((a, b) => b.score - a.score)
const winner = ranked[0]
const CLOSE_MARGIN = 0.05
const closeCall = ranked.length > 1 && winner.score - ranked[1].score < CLOSE_MARGIN
const weightText = `tests ${W.tests / weightSum}, legibility ${W.legibility / weightSum}`
log(`Winner: ${winner.coder} (score ${winner.score}: ${winner.passed}/${winner.total} tests, legibility ${winner.legibility}/5)${closeCall ? `; within ${CLOSE_MARGIN} of the runner-up` : ''}`)

phase('Test review')
const review = await agent(`You are the test reviewer. Review the unit tests on branch ${tests.branch} (commit ${tests.commit}) against the spec below. The judge has already scored the implementations with these tests; the results are included as evidence.
You are in an isolated git worktree. Check out ${tests.branch}, then create branch ${branchFor('tests-reviewed')} from it.
Look for: expectations that contradict the spec, requirements with no test, brittle tests, tests of implementation details, and tests that could pass against a wrong implementation. A test that every implementation fails deserves a close look: decide whether the test or the implementations are wrong.
Fix clear-cut test errors yourself and commit them to ${branchFor('tests-reviewed')}. Flag anything that depends on the human's intent instead of changing it. Commit even if you changed nothing, so the branch exists. Do not edit implementation code.

${SPEC}

The tester's coverage map: ${tests.coverage.length ? JSON.stringify(tests.coverage) : 'not provided; build it from the test files yourself'}
The tester's assumptions: ${tests.assumptions.join('; ') || 'none'}
Judge results: ${JSON.stringify(judged)}
Notes for the test reviewer: ${spec.roleNotes.testReviewer}

${RULES}`, { label: 'test-reviewer', phase: 'Test review', schema: TEST_REVIEW_SCHEMA, isolation: 'worktree' })
if (!review) log('The test reviewer did not finish; the report covers unreviewed tests')

phase('Report')
const report = await agent(`You compile the final review material for the human who asked for this work. Write a concise Markdown report. Read the branches as needed to check claims; do not modify anything.

Structure:
1. Outcome: what was built, the winning branch, and how to merge it (show the commands, but do not run them). The winning code and the tests are on different branches; say that both are needed and which test branch to use.
2. Scoreboard: a table of every candidate with weighted score, tests passed/total, legibility, and a one-line note. State the weights.
3. Needs human review: a prioritized list with file:line references. Include every spec assumption, every flagged test finding, tests failed by all candidates, uncovered requirements, coder concerns, any close call in the ranking, and anything you spot in the winning diff that a person should check. Say why each item matters.
   The judge scored against the tests BEFORE review. If the test reviewer fixed any test, say which candidates' pass counts that could change and whether it could change the winner.
4. Branches created: list them all so the human can delete them later.

Keep it short; the human will read the code themselves.

SPEC:
${JSON.stringify(spec, null, 2)}

CANDIDATES (entries with baseline: true are existing commits, not coder output; they created no branch):
${JSON.stringify(contenders, null, 2)}

TESTER:
${JSON.stringify(tests, null, 2)}

JUDGE (run against the tester's branch, before review):
${JSON.stringify(judged, null, 2)}

TEST REVIEW:
${review ? JSON.stringify(review, null, 2) : 'The test reviewer did not finish; the tests are unreviewed. Say so prominently.'}

RANKING (weights: ${weightText}): ${ranked.map(c => `${c.coder} ${c.score} (${c.passed}/${c.total}, L${c.legibility})`).join(' > ')}${closeCall ? ` (top two within ${CLOSE_MARGIN})` : ''}`, { label: 'reporter', phase: 'Report' })

return {
  winner: { coder: winner.coder, branch: winner.branch, score: winner.score },
  testsBranch: review ? review.branch : tests.branch,
  weights: { tests: W.tests / weightSum, legibility: W.legibility / weightSum },
  ranked,
  closeCall,
  report,
}

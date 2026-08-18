# GhidraGPT — Test Plan

Headless unit tests. **Ghidra is a compile/classpath dependency only — never executed**
(no headless runs, no project DB, no decompiler execution). Build reads jars from the
path in the local, gitignored `test.env` (`export GHIDRA_INSTALL_DIR=...`);
`pom.xml` and `r-utst.sh` both pick it up from the environment. Verification of
"Ghidra not changed": sha256 of all 13 referenced jars, from a committed manifest at
`src/test/resources/ghidra-baseline.sha256` (paths relative to the Ghidra install root),
re-compared at the end of `r-utst.sh`.

## Run commands

```bash
mvn test          # GHIDRA_INSTALL_DIR is hardcoded in pom.xml; env var NOT required
mvn verify        # + JaCoCo coverage report (target/site/jacoco/index.html)
```

## Status legend

- `[x]` = implemented and green in `mvn test`
- `[ ]` = not started
- `[!]` = blocked / needs decision

---

## Phase 0 — Build infra (pom.xml)

- [x] JUnit Jupiter 5.10.2 (test scope)
- [x] Mockito 5.17.0 (test scope; inline mock maker, JDK 21 compatible)
- [x] OkHttp MockWebServer 4.12.0 (test scope — matches runtime okhttp version)
- [x] Pin maven-surefire-plugin 3.5.4 (JDK 21)
- [x] JaCoCo 0.8.15 (prepare-agent + report on verify)
- [x] `ghidra.install.dir` set via env var `GHIDRA_INSTALL_DIR` (local `test.env`, gitignored; `pom.xml` reads `${env.GHIDRA_INSTALL_DIR}`)
- [x] Smoke test runs green

## Phase 0.5 — Minimally needed seams for testability (behavior-identical)

- [x] `ConfigurationManager`: instance `configPath`; new constructor `ConfigurationManager(Path baseDir)`; no-arg delegates to `~/.ghidragpt`
- [x] `APIClient`: package-private `APIClient(int timeout, OkHttpClient client)`; endpoint URL constants (e.g. `OPENAI_API_URL`) + model-list URL builders become overridable package-private for MockWebServer retargeting
- [x] `FunctionRewrite`: package-private constructor accepting `DecompInterface`; visibility bump of pure methods (parse/prompt/extractors/normalizers/resolvers) from `private` to package-private
- [x] `CodeAnalysis`: package-private constructor accepting `DecompInterface` + `FunctionRewrite`; prompt builders package-private
- [x] No behavior change: `target/GhidraGPT-1.4` production paths untouched

## Phase 1 — `utils`

**`ResponseParserTest`**
- [x] `extractFunctionCode`: JSON `code` key
- [x] `extractFunctionCode`: JSON `function` key
- [x] `extractFunctionCode`: JSON `rewritten_code` key
- [x] `extractFunctionCode`: fenced code block (valid function heuristic: `()` `{}` + modifier, ≥10 chars)
- [x] `extractFunctionCode`: fenced block that is NOT valid code → falls through
- [x] `extractFunctionCode`: bare function pattern fallback
- [x] `extractFunctionCode`: raw code fallback; empty/null → null

**`SuggestionApplierTest`**
- [x] `parseVariableSuggestions`: `old -> new: reason` (with reason)
- [x] `parseVariableSuggestions`: without reason; multiple lines
- [x] `parseVariableSuggestions`: invalid new name (keyword) is excluded
- [x] `isValidVariableName`: null/empty; digit-leading; `_`-leading; C keywords; valid names
- [x] `extractCodeBlock`: fenced ```c block; no-marker heuristic
- [x] `generateSuggestionReport`: contents (function name, totals, applied lines)
- [x] `applyVariableSuggestions`: local var applied; param applied; duplicate-name exception skipped (counted not applied)

**`PromptBuilderTest`**
- [x] `addSection` format (`title:\ncontent\n\n`)
- [x] `addInstructions` / `addExamples` / `addNotes` labels
- [x] `createFunctionAnalysisPrompt` includes function name + code

**`GhidraFunctionModifierTest`** (needs `Program` mock)
- [x] `updateFunctionName`: null/empty/identical → false
- [x] `updateFunctionName`: symbol exists → false (no rename)
- [x] `updateFunctionName`: success → true (verify `function.setName`)
- [x] `updateFunctionComment` / `updateFunctionRepeatableComment`: null/blank → false, else true + verify
- [x] `isValidFunctionName`: reserved words; invalid chars; valid

## Phase 2 — `service` domain models (mocked only)

**`VariableAnalysisTest`**
- [x] category: parameter → PARAMETER
- [x] category: `iVar1`-style → TEMPORARY
- [x] category: `local_xxx` / `uStack_xxx` → STACK
- [x] category: cap-first long name → WELL_NAMED; else LOCAL
- [x] `needsTypeAnalysis`: undefined, int, uint, void* true; typed false
- [x] `getTypeDisplayName`: null type → "unknown"

**`FunctionAnalysisTest`** (mock `Function`/`Parameter`/`DataType`/`AddressSet`)
- [x] signature format `ret name(type a, type b)`
- [x] complexity boundaries: SIMPLE / MODERATE / COMPLEX / VERY_COMPLEX
- [x] `needsAnalysis` (complexity, issues, unclear-type vars)

## Phase 3 — `config/ConfigurationManagerTest` (temp dir via new constructor)

- [x] fresh dir: defaults (provider OPENAI, model gpt-4, encrypted key empty)
- [x] round-trip: provider/model/apiKey + all numeric & string properties (save → new instance → assert)
- [x] XOR crypto: stored raw value is hex, not plaintext; get/set round-trip
- [x] empty key → "" and `isApiKeyEncrypted` false
- [x] `canDecryptStoredKey` true (no/stored key); `reEncryptApiKey` empty → false, real → true + changes
- [x] `isConfigured`: OPENAI no-key → false; key+model → true; OLLAMA keyless → model-only rule; OPENAI_COMPATIBLE needs key+model+URL
- [x] invalid provider string → fallback OPENAI
- [x] corrupt config file → defaults created
- [x] `getTimeoutSeconds`: corrupt value → default
- [x] file persists across instances; `configurationFileExists`

## Phase 4 — `service/APIClientTest` (MockWebServer, all 9 providers)

- [x] OPENAI: endpoint (default URL), `Authorization: Bearer`, body {model,messages,max_tokens,temperature,stream}, SSE chunks accumulate, `[DONE]` ends, result returned; partial callbacks
- [x] ANTHROPIC: endpoint, `x-api-key` header, `content_block_delta`/`text_delta` accumulation
- [x] GEMINI: endpoint, Bearer, OpenAI-compatible SSE accumulation
- [x] COHERE: endpoint, Bearer, `content-delta` accumulation
- [x] MISTRAL: endpoint, Bearer, OpenAI SSE accumulation
- [x] DEEPSEEK: endpoint, Bearer, OpenAI SSE accumulation
- [x] GROK: endpoint, Bearer, model fallback `grok-beta`, OpenAI SSE accumulation
- [x] OLLAMA: no auth header; body model/messages/system prompt/options (num_predict/num_ctx/temperature/top_p/top_k); thinking=false → penalties included (presence/repeat/repeat_last_n=256); thinking=true → NO penalties
- [x] OLLAMA stream: JSONL frames accumulate content; `[DONE]`-style last frame captured: stats (prompt/eval counts, tok/s, done_reason)
- [x] OLLAMA thinking: native `thinking` field → `onThinkingResponse`; `getLastThinkingContent`
- [x] pre-check: non-OLLAMA without key → `IllegalStateException`
- [x] pre-check: OPENAI_COMPATIBLE without custom URL → `IllegalStateException`
- [x] OPENAI_COMPATIBLE: custom URL normalization (bare, `/v1`, `/v1/`, with trailing route); Bearer auth
- [x] HTTP 500 → `IOException` + `onError` invoked
- [x] `fetchAvailableModels`: OpenAI (gpt-filter, sorted), Ollama (sorted), compatible (models endpoint), Gemini (models/ strip, gemini- filter); unsupported provider → empty list; HTTP error → empty list

## Phase 5 — `FunctionRewrite` (pure logic; mocked `Function`, temp-dir config)

**Prompt generation** (`generateComprehensiveRewritePrompt`)
- [x] custom instructions included at top (and omitted when empty)
- [x] function name + decompiled code present
- [x] parameters section; SEH vars skipped (`unaff_FS_OFFSET`, `puStack_*` undefined1)
- [x] temp vs stack var sections (decompiler-name rules); `iVar1` → temp
- [x] re-rename toggles: named locals / m_ fields / F_MV functions / C_ classes appear only when enabled
- [x] globals section (only default-named `globalRefs`; others skipped)
- [x] struct member fields & function-call & class-reference sections extracted
- [x] JSON skeleton + Examples + address notes present

**JSON parse** (`parseComprehensiveRewriteResponse`)
- [x] full JSON: all maps populated (function_name/prototype/renames/types/comments/globals/fields/functions/classes)
- [x] duplicate keys → FIRST wins (function_name and object values)
- [x] `this->field_0x…` keys stripped from variableRenames/variableTypes
- [x] type normalization `INT`→`int` etc. (single-token upper only)
- [x] `function_renames` values `::` → `_`
- [x] `field_renames` merged into variableRenames
- [x] truncated JSON → partial maps kept
- [x] no JSON → text fallback (FUNCTION_NAME/RENAME/TYPE_HINT)

**Classifiers/normalizers** (table-driven)
- [x] `isDecompilerGeneratedName`: param_1, local_aa, local_F1_10, puStack_10, iVar1, Var1, in_, extraout_, unaff_, temp_ → true; myVar, userFoo → false
- [x] `isDefaultGlobalName`: DAT_/FUN_/cls_/LAB_/s_/PTR_/EXT_/meth_0x/ + leading-underscore variant; user names → false
- [x] `isCodeLabel`: LAB_/vftable_/switchD_/caseD_
- [x] `isMemberFieldName` / `isDefaultFieldName`
- [x] `normalizeToCamelCase`: snake_case, mFoo, m_foo, Foo
- [x] `normalizeToPascalCase`: M_Foo→Foo, m_foo→Foo, foo→Foo
- [x] `isValidFunctionName` / `isValidVariableName` (incl. reserved-word, char tables)
- [x] `resolveDataType` (mocked DataTypeManager): exact match, `P`-prefix → Pointer, int/uint/dword/word/bool/void, unknown → `/int` fallback

**Extractors**
- [x] `extractMemberFieldReferences`: dedupe, accessor examples
- [x] `extractFunctionCallReferences`: `FUN_*` + `::meth_0x*`
- [x] `extractClassReferences`: cls_/C_*/namespace calls; OOAnalyzer excluded; Windows typedefs excluded

## Phase 6 — `FunctionRewrite` pipeline/apply (mocked Ghidra types + injected DecompInterface)

- [x] `openProgram` false → result error "Failed to initialize decompiler"
- [x] null `DecompileResults`/highFunction → decompile-failure error result
- [x] debug `"load"`: AI response read from file path (dir only / dir+file); missing file → error; LLM **never** called
- [x] debug `"save"`: prompt/response(+thinking) files written to debug path
- [x] thinking threshold: prompt < thresholdKB → `setEnableThinking(false)` on client
- [x] user cancellation before apply → "Operation cancelled..." result (no exception)
- [x] full happy path: mocked decompile + canned JSON from `APIClient` → spec applied: function rename recorded, outcomes listed
- [x] apply-function-rename off (config) → no rename
- [x] `applyGlobalRename`: symbol found → renamed; non-default name → skip; `DAT_` address fallback path; unknown → false
- [x] `applyComment`: address inside body → EOL comment (verify `Listing.setComment`); address-0x400000 fallback; entry+offset fallback; unresolvable → false
- [x] `applyGlobalTypeChange`: symbol found + undefined type → `Listing.createData` w/ new type; already-typed → skip reason; address-only fallback via `DAT_`; unresolvable type → reason
- [x] `checkFullCommit`: non-parameter symbol → false; parameter-count mismatch → true
- [x] `applyVariableRenameBatch` (mocked LocalSymbolMap/HighSymbol): known local → renamed via `HighFunctionDBUtil` (mockStatic); hallucinated name → pre-filtered (not in results); `LAB_` name → dropped; duplicate-target → only first applied
- [x] `EnhancementResult.getReport`: rendering of renamed function, OK/FAIL outcomes, errors

## RESUME STATE — **C-GAPS CLOSED (193/193 PASS); A + B open**

**Final status (verified via `./r-utst.sh`, 2026-08-18):**
- Full suite: **193 tests, 0 failures, 0 errors, 0 skipped**
  - `FunctionRewritePipelineTest` 16 (+1 annotated-code, +4 console = 9 new since Phase 6)
  - `APIClientTest` 28 (+8: 3 Ollama guard-rails, 3 HTTP-500, 2 model-fetch)
- `FunctionRewritePromptGenTest.java` (Phase 5): **23/23 PASS**
- `FunctionRewriteApplyTest.java` (Phase 6): **24/24 PASS**
- Phase A (dead code) + Phase B (hygiene): **still open** — see follow-up list.
- `mvn -q package -DskipTests` → `target/GhidraGPT-1.4.zip` produced (production build OK)

**Last 3 fixes applied this session (all in `FunctionRewriteApplyTest.java`):**
1. `applyGlobalRename_unknown_returnsFalse` — added `AddressFactory` stubs (falls into `DAT_` address-fallback branch)
2. `applyVariableRenameBatch_knownLocal_renamed` — removed illegal `when(...).thenReturn(null)` on static-mocked **void** `commitParamsToDatabase` (mockStatic default is no-op)
3. `applyVariableRenameBatch_duplicateTarget_onlyFirstApplied` — assert via `oldName` lookup (dedup entries precede the successful one in the results list)

**Key APIs to remember (for future work):**
- `SymbolIterator` is `Iterator<Symbol> + Iterable<Symbol>` (implement `java.util.Iterator<Symbol> iterator()`)
- `AddressFactory` is `ghidra.program.model.address.AddressFactory`
- `Program.getDataTypeManager()` returns `ProgramBasedDataTypeManager`
- `HighFunctionDBUtil` is in `ghidra.program.model.pcode` (Decompiler jar); `commitParamsToDatabase` is **void**
- `function.getBody()` returns `AddressSetView` (`.contains(Address)`, `.getNumAddresses()`)
- Package-private ctor: `FunctionRewrite(APIClient, Console, ConfigurationManager, DecompInterface)`
- `SuggestionApplier.isValidVariableName` static in `ghidragpt.utils`
- **Mockito rule:** never call a helper that creates Mockito stubs inside another `when(...).thenReturn(helper())` → `UnfinishedStubbingException`. Hoist helper result to a local, or make the helper non-Mockito (anonymous impl / JDK Proxy).
- `isDefaultGlobalName` regex: `(DAT|FUN|cls|LAB|PTR|EXT|s|switchD|caseD|GUID|thunk_FUN|AddrTable)_[0-9a-fA-Fx]+` (hex-ish only after the `_`)
- `applyComment` base-adjust fallback: `adjusted = rawAddr - 0x400000`



## Phase 7 — `CodeAnalysisTest`

- [x] `rewriteFunction` unconfigured (OPENAI no key) → configuration error string incl. provider/model/key status; delegates NOT called
- [x] `rewriteFunction` configured (OLLAMA keyless / OPENAI) → `FunctionRewrite.EnhancementResult.getReport()` returned; delegate called exactly once
- [x] `rewriteFunction` delegate throws → `"Error during function rewrite: " + msg` returned (no exception propagates)
- [x] `detectVulnerabilities`: decompile failed / null results → `"Failed to decompile function: <name>"`
- [x] `detectVulnerabilities` unconfigured → config error string; `sendRequest` NOT called
- [x] `detectVulnerabilities` configured → `StreamCallback` invoked (onPartialResponse/onComplete), console lifecycle called (header / streamHeader / appendStreamingText / streamComplete), response returned
- [x] `detectVulnerabilities` API IOException → `"API Error: <msg>"`
- [x] `explainFunction`: decompile failed → failed; unconfigured → config error; configured → streamed (verify console `function explanation` ops); IOException → `API Error: <msg>`
- [x] `buildVulnerabilityPrompt` content: prefix, `Context:` (symbol block), `Code:`, `STRICT CRITERIA`, "No exploitable vulnerabilities detected."
- [x] `buildExplanationPrompt` content: `CONCISE FUNCTION ANALYSIS for: <fn>`, `Code:`, `[•] Purpose`, `[»] How it works`, 150-word cap
- [x] `initializeDecompiler` → `setOptions` + `openProgram` called; `dispose` → both `decompiler.dispose()` + `functionRewriteService.dispose()`

## Phase 8 — Final verification

- [x] `mvn test` fully green (no skipped, no ignored) — 193 run, 0 failures, 0 errors, 0 skipped
- [x] `mvn -q package -DskipTests` still produces `target/GhidraGPT-1.4.zip` (production build unaffected)
- [x] re-hash Ghidra install jars → identical to committed `src/test/resources/ghidra-baseline.sha256` (Ghidra NOT modified; no `~/.ghidragpt` written by tests)
  - 13 reference jars: `( cd $GHIDRA_INSTALL_DIR && sha256sum -c ../src/test/resources/ghidra-baseline.sha256 )` → all OK
  - `~/.ghidragpt` absent after test run (config tests use `@TempDir`)
  - Manifest is git-tracked, so the guard no longer depends on ephemeral `/tmp` state.

## Explicitly excluded (Swing/GUI — no unit value)

`ui/Provider`, `ui/GhidraGPTProvider`, `ui/ConfigurationPanel`, `ui/Console`, `GhidraGPTPlugin`

## Phase 9 — Review vs `w-next` + planned gap-closing (NOT yet implemented)

Reviewed `w-utst` vs its merge-base `w-next` (ec08998). Conclusion: **plugin
functionality intact** — all production diffs are behavior-preserving test seams
(visibility widening, injectable ctors, same-valued URL constants). No deletions,
no packaging changes (`Module.manifest`, `extension.properties`, `src/assembly`
untouched). 193/193 green; `target/GhidraGPT-1.4.zip` builds.

### Test gaps found (highest value first)

1. `FunctionRewrite` console interaction — **CLOSED** (4 new tests in `FunctionRewritePipelineTest`).
   Covers: `printAnalysisHeader` + `appendOptions` (argument assertions via
   `ArgumentCaptor<String[][]>`), `printStreamHeader` (once on first chunk),
   `appendStreamingText` per partial, `appendThinkingText`, `printStreamClose`,
   `printStreamError`, and thinking-threshold `appendInfo` + `setEnableThinking(false)`.
2. `generateAddressAnnotatedCode` + `collectTokens` — **CLOSED**
   (`FunctionRewritePipelineTest.pipeline_producesaddressAnnotatedCode_inPrompt`).
   Drives the real `rewriteFunction` pipeline with a mock `ClangTokenGroup` tree
   (`ClangToken`/`ClangBreak` — concrete non-final, no Ghidra run) so the
   address-annotation logic emits `/* 0x… */`-prefixed lines and the prompt is
   verified to contain them.
3. Ollama guard-rails — **CLOSED** (3 new tests in `APIClientTest`):
   - max-response-size cap → `cancelReason` set, generation cancelled, notice pushed via
     `onPartialResponse` (`ollama_maxResponseSizeCap_cancelsAndReports`).
   - `tps`-zero fallback when `eval_duration` absent
     (`ollama_noEvalDuration_tpsFallbackZero`).
   - partial ` thinking` tag split across two chunks → buffer/reassemble; body
     routes to `onThinkingResponse`, text before/after to `onPartialResponse`
     (`ollama_thinkTagSplitAcrossChunks_buffersAndReassembles`).
   - Not unit-tested: thinking-**timeout** (time-based, `processingTimeoutMinutes`
     floor is 1 min ⇒ non-deterministic without a clock seam).
4. HTTP-error branches — **CLOSED** (3 new tests in `APIClientTest`):
   `http500_anthropic_throwsIOException`, `http500_cohere_throwsIOException`,
   `http500_ollama_throwsIOException_andInvokesOnError` (verifies `onError` too).
5. `fetchMistralModels` / `fetchDeepSeekModels` — **CLOSED** (2 new tests in
   `APIClientTest`: `fetchMistralModels_sorted_usesBearer`,
   `fetchDeepSeekModels_sorted_usesBearer`).
6. `FunctionRewrite` 3-arg ctor + `createDecompiler()`; real `dispose()` body;
   `ConfigurationManager` encrypt/decrypt catch-fallback branches.

### Dead code confirmed unreferenced (candidates for removal)

- `APIClient`: `sendOpenAIRequest`, `sendAnthropicRequest`, `sendGeminiRequest`,
  `sendCohereRequest`, `sendMistralRequest`, `sendDeepSeekRequest`, `sendGrokRequest`
  (all non-streaming builders; switch routes everything to streaming),
  `StreamingUtils.simulateStreaming`.
- `CodeAnalysis`: `createEmptyResponseError()`.
- `ConfigurationManager`: `migrateToEncryptedApiKey()` (deprecated no-op).

### Minor hygiene

- `pom.xml` lines 113–115: duplicated comment block.
- `APIClient` URL constants lost `final` (now mutable `static`) — consider restoring
  immutability via a package-private test setter.

### Agreed follow-up (deferred — revisit later)

- [x] **A. Remove dead code** (APIClient builders/simulateStreaming, createEmptyResponseError,
      migrateToEncryptedApiKey). **193/193 green** after removal (−317 lines total).
- [x] **B. Hygiene** — dedupe pom comment. URL constants keep `static`-mutable form
      (accepted decision 2026-08-18; `setEndpointForTesting` pattern rejected as
      over-engineered).
- [x] **C1. Close gap #1** — console-interaction tests (mock `Console`, no Ghidra
      run). 4 new tests in `FunctionRewritePipelineTest`: header/options, streaming
      chunks, thinking + stream-error, thinking-threshold annotation.
- [x] **C2. Close remaining gaps** — 8 new tests total:
      - `FunctionRewritePipelineTest.pipeline_producesaddressAnnotatedCode_inPrompt`
        (mock `ClangTokenGroup`/`ClangToken`/`ClangBreak` tree through the real
        `rewriteFunction` path → `/* 0x… */`-annotated prompt).
      - `APIClientTest`: `ollama_thinkTagSplitAcrossChunks_buffersAndReassembles`,
        `ollama_maxResponseSizeCap_cancelsAndReports`, `ollama_noEvalDuration_tpsFallbackZero`,
        `http500_anthropic/…`, `http500_cohere/…`, `http500_ollama_…(onError)`,
        `fetchMistralModels_sorted_usesBearer`, `fetchDeepSeekModels_sorted_usesBearer`.
      All headless (MockWebServer + mocked non-final Clang classes; Ghidra never executed).
      (Skipped: Ollama thinking-**timeout** — time-based, no clock seam.)

# Behavior Corpus

| Scenario ID | Title | Proof seam | Run cadence | Command | Owning stories |
|---|---|---|---|---|---|
| JOURNEY-0001 | A concrete conditional call is approved and executed | e2e | sentinel | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3FetchRefusesDeniedRedirectedOversizedAndTimedOutDocuments)$' -count=1` | STORY-0001, STORY-0002, STORY-0003, STORY-0004 |
| SCENARIO-0001 | Proposal structure is strict | unit | iteration | `go test . -run '^(TestR3ProposalBindsInlineAndDigestParameters|TestR3ProposalRejectsMalformedParameterDocuments|TestR3DocumentRejectsDuplicateNamesAtEveryDepth)$' -count=1` | STORY-0002 |
| SCENARIO-0002 | Challenge token carries only the proposal reference | integration | iteration | `go test . -run '^TestR3ConditionalPerCallJourney$' -count=1` | STORY-0002 |
| SCENARIO-0003 | Proposal construction and custody fail closed | integration | iteration | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreRejectsUnsafeDirectoryPermissions|TestFileR3PerCallIssuanceStoreRejectsUnsafeDirectoryPermissions|TestFileR3DocumentStoreRefusesOversizedOrInvalidRetention|TestFileR3DocumentStoreCountsProposalStateAgainstTotalByteLimit|TestFileR3DocumentStoreRollsBackNewDocumentWhenProposalStateCannotFit)$' -count=1` | STORY-0002 |
| SCENARIO-0004 | Ungranted operations never execute | integration | iteration | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3DirectGrantJourney|TestValidateR3AuthorizationDecisionAcceptsOnlyDisjointDocumentSubsets)$' -count=1` | STORY-0001 |
| SCENARIO-0005 | Proposal authorization cannot be partial or recursive | integration | iteration | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3TokenClaimsRequireCompleteConsistentClaims|TestValidateR3AuthorizationDecisionRequiresExactDirectProposalGrant|TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart)$' -count=1` | STORY-0003 |
| SCENARIO-0006 | Every actual parameter remains bound | e2e | sentinel | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestR3ProposalBindsInlineAndDigestParameters|TestR3ProposalRejectsMalformedParameterDocuments|TestClassifyR3ProposalReferenceRefusesDigestPathMismatch|TestAgentRefusesProposalStageWithMismatchedDigestPath)$' -count=1` | STORY-0004 |
| SCENARIO-0007 | Resource reconstruction retains enforcement | integration | sentinel | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreFailsClosedForMissingExpiredOrCorruptProposalCustody|TestFileR3PerCallIssuanceStoreCommitsOneExactTokenAcrossRestart)$' -count=1` | STORY-0005 |
| SCENARIO-0008 | Replayed proof and per-call token reuse are refused | integration | sentinel | `go test ./... -run '^(TestR3ConditionalPerCallJourney|TestFileR3DocumentStoreConsumesProposalOnceAcrossRestart)$' -count=1` | STORY-0005 |
| JOURNEY-0002 | One public subscription delivers one verified event | e2e | sentinel | `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1` | STORY-0006 through STORY-0015 |
| SCENARIO-0009 | Invalid self-jwt fails before discovery | integration | iteration | TBD | STORY-0006 |
| SCENARIO-0010 | One discovered key must verify both proof layers | e2e | sentinel | TBD | STORY-0006, STORY-0007, STORY-0012, STORY-0013 |
| SCENARIO-0011 | Presenter-directed discovery stays inside host policy | integration | iteration | TBD | STORY-0007 |
| SCENARIO-0012 | Current AP metadata controls delivery endpoint | integration | iteration | TBD | STORY-0008, STORY-0012 |
| SCENARIO-0013 | Subscribe-token mutations cannot register | integration | iteration | TBD | STORY-0009, STORY-0011 |
| SCENARIO-0014 | Duplicate public registration cannot replace custody | process-level | sentinel | TBD | STORY-0011 |
| SCENARIO-0015 | Durable-inbox failure prevents 202 | process-level | iteration | TBD | STORY-0013 |
| SCENARIO-0016 | Concurrent final use has one durable winner | process-level | sentinel | TBD | STORY-0012, STORY-0013 |
| SCENARIO-0017 | AP refusal classes leave state unchanged | integration | iteration | TBD | STORY-0013 |
| SCENARIO-0018 | Agent verification and dedup survive reconstruction | process-level | sentinel | `go test -race ./reference -run '^(TestAgentEventProcessing|TestEventAdapter)' -count=1` | STORY-0014, STORY-0015, STORY-0016 |
| SCENARIO-0019 | M5 remains payload-free and claim-honest | integration | iteration | TBD | STORY-0010, STORY-0014, STORY-0016 |
| SCENARIO-0020 | AP issuance cannot outrun subscription custody | process-level | sentinel | TBD | STORY-0009 |
| SCENARIO-0021 | Host custody failure prevents outward success | process-level | iteration | TBD | STORY-0010, STORY-0011, STORY-0015 |
| SCENARIO-0022 | Two APs may reuse one opaque eid | process-level | iteration | TBD | STORY-0011 |
| SCENARIO-0023 | Unknown delivery outcome retries one exact token | process-level | sentinel | TBD | STORY-0012, STORY-0013 |
| SCENARIO-0024 | Host stores are versioned replaceable authorities | process-level | sentinel | TBD | STORY-0009, STORY-0010, STORY-0011, STORY-0012, STORY-0013, STORY-0014, STORY-0015, STORY-0017 |

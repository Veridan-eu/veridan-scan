#Requires -Version 7.0
<#
    Invoke-VeridanCollection.ps1   v0.8.23

    v0.8.23 - #52: THE HTTP STATUS IS SAID ONCE.
      Cosmetic, text only. The five call sites already write "(HTTP <n>)"
      before the reason, and v0.8.22's Get-VdnDenialReason repeated it for a
      401 and for every non-denial status: "sign-in logs unreadable
      (HTTP 503) - not a licence or permission answer (HTTP 503) ...; see
      status". The reason no longer carries the status; "see status" went
      with it. When Graph gave no status at all (an authentication error
      raised before any request), the reason says "(no HTTP status)".
      Found by tests\Test-CollectorFunctions.ps1, the first check of the
      warning TEXT - the simulator compares dataset, kind and status only,
      which is how #48 got through 447/447. Codes, statuses, aggregates and
      datasets are unchanged.

    v0.8.22 - O-9: THE COLLECTOR CHECKS WHERE IT LANDED BEFORE IT READS.
      Until now the connected tenant was only printed. Two checks run right
      after Connect-MgGraph and before the first data call; either one
      disconnects and stops with no output file:
        1. -TenantId given, and the context reports a different tenant.
           Defence in depth - Connect-MgGraph -TenantId should never do that.
        2. The tenant is listed in forbidden-tenants.txt next to this script
           (one GUID per line, '#' starts a comment). The file is optional
           and is NOT shipped: it lives on our own machines, where the same
           Windows account is also signed in to our production tenant. A Free
           run without -TenantId goes to the account's default tenant, which
           on such a machine can be production. The check protects exactly the
           run where somebody forgot the parameter - a parameter could not.
      A customer's run is unchanged: no file, and -TenantId matches.
      #48 - my own regression in v0.8.21, found in review, not by the
      simulator (Compare matches warnings on dataset/kind/status, never on
      text): Get-VdnDenialReason worded EVERY failure as licence-or-
      permission, so a 503 on the registration report, the sign-in probe or
      CA read "Entra ID P1 or <permission> missing". It now takes -Status:
      only a 403 or a denial code names those causes; a 401 says token; any
      other status says "not a licence or permission answer ... transient or
      service failure". The directory-audit warning goes through it too, with
      no licence named (audit logs need none).

    v0.8.21 - #47: A 403 NAMES ITS CAUSE ONLY WHEN GRAPH DOES.
      Measured 28 Sep with a deliberately reduced app registration (six of
      the eight permissions, no AuditLog.Read.All, no Reports.Read.All) on the
      lab tenant, which HAS Entra ID P1: three of the four 403 warnings said
      "Entra ID P1 required" and carried code null. The text was a constant
      written on 18 Sep, when a missing licence was the only 403 we had seen.
      A customer with P1 whose app registration lacks one permission would
      have read "you have no P1" in the dossier - the #44 class again.
        - Every Add-CollectionWarning for an HTTP failure now passes -Code
          (Graph's error.code; identifier-free, ships in Free mode as well).
        - The four licence-or-permission sites (users signInActivity, the
          registration report, CA policies, the sign-in log probe) word the
          cause through Get-VdnDenialReason: licence only when the code says
          licence, permission only when the code says permission, and
          "licence or permission" otherwise. Authorization_RequestDenied is
          deliberately in the last group - it is what Graph says for a
          missing directory role and for a missing consent alike.
      Aggregates, datasets and every *Available flag are unchanged; only the
      warnings' code and message move. The live confirmation is the same
      reduced-app Full scan, run again on this version.

    v0.8.20 - CONTRACT 0.3 (Vasil, For_Koko-0.3, 24 Sep; his list said
    "0.8.18", but 0.8.18 (#44) and 0.8.19 (D-007) were already taken).
      1. schemaVersion '0.3'. Same shape as 0.2 plus the fields below;
         requestedPermissions is now an object array and the licence fields
         are nullable IN THE SCHEMA (D-028) - nothing to change here.
      2. authMethods[].userType is normalised to Guest | Member (D-025). The
         report returns it lower-case ("guest"); the users dataset returns it
         capitalised; the schema enum is capitalised. Measured 22 Sep.
      3. mfaNotRegistered and unlicensedEnabled EXCLUDE guests (D-025). A guest
         is somebody else's user: their MFA and licence are the home tenant's
         business. The lab said 16 / 2 with two PendingAcceptance guests; the
         customer's own figure is 14 / 0. identity.guests still counts them.
      4. telephonyOnly requires isMfaRegistered (D-024): "every registered
         method is telephony" AND the report counts it as MFA. When SMS and
         voice are disabled in the tenant policy the report says
         isMfaRegistered false for a phone-only user - that user has NO
         second factor today, which is the next field, not this one.
         adminsTelephonyOnly follows. The lab moves 10 -> 0.
      5. NEW authentication.registeredButNotMfaCapable: registered something,
         and the report still says not MFA-registered. The "has a phone the
         policy forbids" signal found in the lab on 22 Sep (10 users). null
         with the other report figures when the report is not usable.
      6. NEW conditionalAccess.requiresMfaMicrosoftManaged /
         requiresMfaCustomerCreated: the enabled+mfa count split by origin
         (D-023). They sum to requiresMfa. Lab: 3 / 0.
      7. inactiveByLastSignIn: the age exemption is ageDays < threshold, so an
         account exactly threshold days old is NOT exempt (-ge, was -gt).
         Unknown age stays not exempt (D-027).
      8. templateId is not hashed under -Anonymise - already true since
         v0.8.12; evidence in the 24 Sep anonymised lab scan.
    And two more that validate 0.3 found on the first simulator smoke run of
    this version (28 Sep) - both shared assumptions between collector and
    generator, the #40 class again:
      #45 identity.inactiveByLastSignIn counted DISABLED accounts. The IDN-014
          record scope is accountEnabled true; the aggregate now is too.
      #46 logging.meldplicht.retentionInferredFrom was the constant 'licence'
          even when the licence was never read; null with the rest (D-028).

    v0.8.19 - PER-ENGAGEMENT PSEUDONYMS (D-007): -AnonymisationSalt. The
    engine's decision D-007 (schema README) says an anonymised collection is
    keyed per engagement - HMAC-SHA256 with a key from Key Vault - so a re-scan
    after remediation can be compared pseudonym for pseudonym. The collector
    only ever had the per-run random salt: two anonymised scans of the same
    client shared nothing. -AnonymisationSalt takes a SecureString on purpose
    (a plain string on the command line lands in PSReadLine history on disk),
    requires -Anonymise, refuses a key shorter than 16 characters, and never
    reaches the output, the console or an error. Without it nothing changes:
    same per-run salt, same SHA-256 construction as before.

    v0.8.18 - -SkipSignInActivity NOW SAYS SO (#44). Found live, 24 Sep: a
    Full run with the switch on the lab (which HAS P1) produced a file with
    signInDataAvailable false and no warning at all - indistinguishable from
    a tenant without P1 except that it lacked the reason. The engine's
    not_evaluated text for the sign-in rules would then tell a P1 customer
    they need P1. An info warning (dataset usersSignInActivity, code
    SkippedByOperator) now carries the real reason; Free keeps it, because
    a code is an identifier-free string.

    v0.8.17 - THREE NULL-VS-ZERO DEFECTS, FOUND BY THE ENGINE'S 0.2 VALIDATOR
    RUN OVER ALL 447 SIMULATOR OUTPUTS (24 Sep). The simulator's own oracle
    could not see them - it compares aggregates, and all three live in
    places it does not look. Each is D-002 in a new place:
      #41 registrationReportRows was 0 when the report could not be read at
          all (403 / no P1). 0 rows means "read it, empty"; unread is null.
          177 of 447 runs.
      #42 users[].neverSignedIn / inactiveByLastSignIn were computed from a
          signInActivity that was never fetched - so with no P1 EVERY account
          read as never-signed-in and inactive. The aggregate was gated; the
          records were not. Now null on the record when sign-ins are unknown.
          100 of 447 runs (every Full run on a tenant without P1).
      #43 groups[].memberIds / nestedGroupIds / ownerIds were [] when the
          per-group call failed. [] means "read it, none"; a join against []
          is a silent false negative (IDN-005). Now null. 62 group rows.
    Also: the D-004 age exemption in the aggregate no longer exempts an
    account whose age is UNKNOWN (ageDays null) - unknown is not young.

    v0.8.16 - THE ENGINE'S VALIDATOR CAUGHT US (#40) + schema 0.2 conformance.
    Running Vasil's validate.py (schema 0.2) against the real 22 Sep Full scan:
    requiresMfa counted every policy whose controls include mfa - INCLUDING
    report-only (D-009 says enforced only). The lab said requiresMfa 4 when 3
    are enforced; the fourth was our own report-only CA001. The simulator
    never caught it because the generator counted the same way - the same
    shared-assumption failure as #39, in the opposite direction: this time
    THEIR implementation caught OURS. Fixed: requiresMfa and appliesToAllUsers
    count ENABLED policies only. Also for 0.2: identity.inactiveThresholdDays
    is emitted (D-004) and the inactive AGGREGATE applies the age exemption -
    an account younger than the threshold cannot be 90-days-inactive (the
    seeded lab said 18 inactive about accounts created the day before);
    users[].inactiveByLastSignIn stays RAW by contract. SCHEMA_VERSION is
    '0.2' - the number belongs to engine/schema, not to this file.

    v0.8.15 - GROUP MEMBERS ARE READ FROM beta: v1.0 /groups/{id}/members
    DOES NOT RETURN servicePrincipal MEMBERS (#39). Found by shape probe B9
    (22 Sep): a group seeded with an SP and a nested group came back from
    v1.0 with ONE member, with and without $select; the SP said memberOf =
    the group, the v1.0 cast /members/microsoft.graph.servicePrincipal
    returned it, and beta /members returned both. Microsoft Q&A and
    azure-cli issue #32774 confirm the behaviour. Until now memberSpCount
    was silently 0 on every tenant, and a group whose only member is an
    application read as EMPTY - a false GRP-001 finding pointing away from
    exactly the thing worth looking at. Owners switched to beta too, by
    symmetry: group owners can also be service principals, and an SP owner
    hidden by v1.0 would fabricate "group without owner" - symmetric but
    UNVERIFIED (no SP-owner probe yet); noted in TESTLOG.

    v0.8.14 - department AND jobTitle SURVIVED -Anonymise (#38). A systematic
    sweep of the anonymised lab file (22 Sep: every string that is not a hash,
    a GUID, a date or a protocol constant) found exactly two fields of customer
    free text left in clear - users[].department and users[].jobTitle. In this
    tenant that printed "EMERGENCY ACCESS - DO NOT DELETE", which names the
    break-glass account in the one file mode meant to be safe to show around,
    and departments ("Audit", "Fiscaal", "Salaris"). A job title is quasi-
    identifying on its own: in a twelve-person company "Directeur" is one
    person. Both now hash like displayName. Nothing in the schema or in
    rules.yaml reads either field, so hashing costs the engine nothing and
    keeps the cardinality a dossier might group by. The salt is a per-run GUID
    that is never written to the file, so the hashes cannot be dictionary-
    attacked back to "Finance".

    v0.8.13 - REPORT COVERAGE IS MEASURED AGAINST ENABLED USERS. The
    registration report turned out to have no row for DISABLED accounts: the
    seeded lab (22 Sep, 26 h after seeding, every other account present)
    showed 19 rows for 21 users, and the two missing were exactly the two
    disabled ones. rows / usersTotal was therefore 0.905 on a report that
    was complete, the 0.95 gate closed and every MFA figure went null on a
    tenant whose MFA state was fully known. Denominator is now the enabled
    users (accountEnabled -ne $false; unknown counts as enabled). A disabled
    account cannot sign in, so its MFA registration is not a risk figure
    either way. Observed once, in one tenant - not documented by Microsoft;
    the simulator models it the same way (census of enabled users).

    v0.8.12 - ANONYMISER BROKE EVERY CROSS-DATASET JOIN (#36). Object ids
    ('id' on users, groups, applications, servicePrincipals, deletedUsers,
    authMethods) were left in clear because 'id' also names authentication
    methods in policies - while memberIds / ownerIds / principalId WERE
    hashed. So users[].id no longer matched groups[].memberIds and the
    engine's IDN-005 (disabled account still in a group) went 2 -> 0 on the
    same tenant, silently; IDN-031 joins users.id to roles.principalId and
    has the same hole. Found by running evaluate.py on the Full and the
    -Anonymise output of the same run (21 Sep). Now: an 'id' whose value is
    a GUID is hashed like every other identifier (method names are not
    GUIDs, so policies.authenticationMethods is untouched); permissionCatalog
    is walked WITHOUT id hashing because its ids are Microsoft catalogue
    constants that applicationPermissions[].appRoleId must keep matching.
    Also hashed from now on: tenantId (names the organisation) and
    companyName (the lab file carried the seeder's name in clear).

    v0.8.11 - CA policies read from beta for templateId; per-policy
    isMicrosoftManaged and aggregate microsoftManaged / customerCreated.
    Trigger: the lab showed 5 policies of which 4 were created by Microsoft
    the second Security Defaults went off (21 Sep). Without the split every
    such tenant reads as "has CA configured".

    v0.8.10 - first live Full/Anonymise runs (21 Sep, seeded lab R02).
      FIRST-PARTY DETECTION HAD A HOLE. "Microsoft Graph Command Line Tools"
      (the Graph PowerShell SDK's own SP) is owned by a third Microsoft tenant
      (cdc5aeea-...) and was counted as a third-party SP without an owner -
      a false AGT-003 finding present in every lab scan since 15 Sep and
      logged on 18 Sep as a "genuine finding". Now: three Microsoft tenants
      plus the verified-publisher id 5206095 as a list-independent signal (#35).

    v0.8.9 - fourth simulator batch: 73 new tenants (constraint-aware pairwise
    Q01-Q56, edge cases D16-D27, realistic seedable profiles R01-R05).

      1. RETRY-AFTER HAS A BUDGET (-MaxRetryAfterSeconds, default 120). Graph
         asking for 900 s was honoured blindly, five times: a 75-minute hang on
         one dataset. Beyond the budget the dataset is recorded unreadable
         (429 + code) and the run moves on. Simulator D23: 1.5 s, was 75 min.

      2. REPORT COVERAGE ONLY FROM A COMPLETE USERS LIST. When page 2 of the
         users call failed, $datasets.users held page 1 and rows/partial-users
         was a confident, meaningless ratio that could clear the 0.95 gate.
         Gated on Test-DatasetOk 'users'. Simulator D16.

      3. THE signInActivity FALLBACK FIRED ON ANY FAILURE. A 503 on page 2
         produced "Entra ID P1 and a directory role are required" and a second
         full read of the directory. Now only 403 / coded 400 fall back;
         everything else is a failed users call and is filed as one. D16.

      4. Coverage above 1.0 (report rows for accounts deleted since its last
         refresh) is flagged as an INFO warning; the MFA counts include the
         ghosts and the engine is told so. Simulator D18.

    v0.8.8 - third simulator batch (76 tenants x Free/Full/FullAnon) + belief
    verification against the 18 Sep lab captures.

      1. WARNINGS CARRY GRAPH'S ERROR CODE. Read from the response body
         (Get-GraphErrorCode), returned by Invoke-Graph as .Code, written into
         every warning as `code` and kept in Free mode: a code such as
         AadPremiumLicenseRequired is a bare identifier - no URI, object ID or
         UPN - so it does not break the "no identifiers" promise the way
         `message` does. Trigger: the lab answers roleEligibilitySchedules with
         HTTP 400 + code AadPremiumLicenseRequired. v0.8.5 read only the status
         and refused to call it a licence problem; the body had said so all
         along. The roleEligibility reason is now code-driven.

      2. ErrorDetails IS NULL ON NON-HTTP EXCEPTIONS and $null.Message is a
         StrictMode error. The first cut of (1) crashed 60 simulator runs on
         it; the same expression had been latent in Get-GraphErrorStatus route
         4 since v0.8.3. Both read through Get-ErrorText now.

      3. /organization FAILING KILLED THE RUN IN PHASE 1 ($o.id on $null). The
         tenant block reads through Get-Prop, carries organizationDataAvailable
         and falls back to the authenticated tenant id (simulator D04).

      4. authorizationPolicy FAILING KILLED THE AGGREGATOR (missing hashtable
         key under StrictMode) and would otherwise have emitted tenantDefaults
         = null against a schema that wants an object. It is now an all-null
         object with dataAvailable=false - valid and honest (simulator D12).

      5. GRANT AND appRoleAssignment ROWS READ THROUGH Get-Prop. principalId is
         null on every AllPrincipals grant; a tenant that omits nulls dropped
         the key and phase 7 died (simulator P07/P09). cross-tenant defaults
         guarded the same way.

      6. TWO SILENT FAILURES NOW WARN: authenticationStrength policies (-Quiet
         with no warning => [] looked like "none defined") and the
         directoryAudits probe (wrote false, said nothing). Simulator D12.

    v0.8.7 - second simulator batch (76 virtual tenants, three modes).

      1. -ANONYMISE HAD NEVER RUN, AND IT BROKE EVERY ARRAY. The walker
         returned @(...) without a leading comma, so PowerShell unrolled empty
         datasets to null and one-element arrays to scalars: ~70 schema
         violations per anonymised file. This is the demo-dossier path.

      2. Dropped free-text ARRAY fields (redirectUris, technicalNotificationMails)
         are emitted as [] instead of the string '(removed)', so the type the
         schema declares survives anonymisation.

      3. GROUPS AND ROLES ARE NOW GUARDED WITH Get-Prop. They were left
         unguarded on the evidence of three Unified lab groups that all carry a
         mail address. Under the collector's own belief that Graph omits null
         properties, Get-VdnGroups crashed on $g.mail. Security groups (which
         have no mail) have never been observed live; the post-seed run will
         say which way Graph goes, but the code no longer depends on it.

    v0.8.6 - first defects found by the VIRTUAL-TENANT SIMULATOR (tests/sim),
    18 Sep evening. The collector ran unchanged against ten virtual tenants;
    three of the findings were collector bugs, all invisible on the real lab
    because the lab has P1, a working licence call and never ran Full mode.

      1. NO-P1 TENANTS LOST EVERY IDENTITY COUNT. The signInActivity fallback
         filed its warning under dataset 'users', which marked the dataset
         failed, so usersTotal / usersEnabled / guests / unlicensedEnabled ...
         were all null even though the fallback call had succeeded - and
         validate.py rejected the file (non-nullable integers). Business
         Standard and Entra Free clients are a large share of the market. The
         degradation now has its own dataset name: usersSignInActivity.

      2. A FAILED LICENCE CALL READ AS "NO LICENCES". subscribedSkus failing
         produced licenceSkus [], unassignedLicences 0, premiumLicencePresent
         false, retentionDaysInEntra 7 -> LIC-001 fails, LOG-001 says 7 days,
         both off an unread dataset. Now gated: licenceDataAvailable, nulls.

      3. FULL MODE: datasets.workloads was null when ScubaGear was skipped;
         the schema types it as object. Every Full file was INVALID. Now an
         object { collected: false, reason }.

    PowerShell 7.0 or later, deliberately nothing newer: Free mode runs on
    the CLIENT's machine, and every version requirement above "PowerShell 7"
    loses a client at the first step of the funnel. Developed and tested on
    7.4/7.6; no 7.6-only features are used or should be added.
    ========================================================================

    v0.8.5 - review fixes, 17 Sep afternoon. Four corrections, one addition.

      1. schemaVersion = '0.1' (D-001). The schema is the ENGINE's contract
         and carries the engine's version. The 1.1-1.6 lineage this script
         maintained was a changelog of the collector's own output shape, not
         a version of normalized.schema.json - one contract, one numbering.
         Verified against engine/schema/validate.py: the version string was
         one of exactly three violations in the 13:45 file. The output-shape
         history stays in this header, where it belongs.

      2. PER-OBJECT SUB-CALLS ARE NOW VISIBLE TO THE AGGREGATOR. Group
         members/owners, app owners and SP owners/appRoleAssignments record
         failures under their own dataset names (groupMembers, appOwners,
         spOwners...), which no availability flag read. A failed owners call
         therefore returned empty, hasNoOwner became true, and
         thirdPartyWithoutOwner / groups.empty FABRICATED a finding from an
         unanswered question - defect #5's pattern, one level down. Row
         fields derived from a failed per-object call are now null, the
         aggregates count only known rows, and the affected sections carry a
         *DataComplete flag so the engine can tell "counted everything" from
         "counted what answered".

      3. registrationReportUsable no longer treats UNKNOWN coverage as full
         coverage. When the users call fails, coverage cannot be computed,
         and the old expression let the report through on a null - in the
         code that exists precisely because partial data burned us on 17 Sep.

      4. roleDefinitions now $selects id,displayName - the full definitions
         carry rolePermissions blobs this script never reads. ($top stays
         absent; the endpoint rejects it.)

      5. Free mode now emits phaseTimings. Phase names and seconds carry no
         identifiers, and "use phaseTimings, not guesses" is this file's own
         rule for optimisation - which was impossible in the one mode
         clients actually run.

    v0.8.1 - two removals, both of things that should not have been written.

      1. REMOVED the probe of 'beta/auditLogs/monitoring/alertRules'. It
         returned HTTP 400 on every run and is not in the Graph v1.0 or beta
         reference; it appears to have been invented when Get-VdnLogging was
         written. Left in place, monitoringConfigured would have been null on
         every tenant forever - half of the meldplicht rule permanently
         reporting "not assessed" while looking like a capability we had.
         Alerting is now stated as not collected, the same way the Azure-side
         diagnostic export is. If the real Entra health-monitoring surface is
         found in the documentation, wire it up then; do not guess again.

      2. REMOVED coversReportingWindow and coversTypicalDwellTime. Both were
         verdicts, not measurements, and they contradicted this collector's
         own principle that thresholds belong in rules.yaml - the same
         principle that keeps inactiveByLastSignIn raw with ageDays beside it.
         "Typical dwell time" is a claim about the threat landscape, not a
         fact about the customer's tenant. Baking 30-days-is-enough into the
         data means one day arguing with a client about a number we put there.
         The collector now emits retentionDaysInEntra and reportingWindowHours
         and lets LOG-001 decide.

      Both are schema-breaking removals, hence 1.4 -> 1.5.

    v0.8.0 - "unknown is not zero", applied everywhere instead of in two
    places. From reading the 17 Sep P1-licensed run.

    THE DEFECT. The 17 Sep file said:

        identity.usersTotal                   3
        authentication.mfaNotRegistered       0     <- false
        authentication.adminsWithoutMfa       0     <- false
        privilegedAccess.globalAdministrators 3

    Two of those three Global Administrators had no authentication method at
    all. The file stated the opposite, in the single figure the product is
    sold on, and it passed every check in v0.7.1 because
    registrationReportAvailable was true - the report HAD answered, with one
    row out of three. The v0.7.0 guard covers an ABSENT dataset. It does not
    cover a PARTIAL one. The registration report lags for hours after a tenant
    is licensed or an account is created, which is the normal state of a
    freshly onboarded client - precisely who runs the free scan.

    WHAT CHANGED

      - registrationReportRows / registrationReportCoverage /
        registrationReportUsable. Below -MinReportCoverage (default 0.95)
        every MFA figure is null and a warning says why. `available` and
        `usable` are reported separately: the report answering and the report
        being trustworthy are different facts.

      - Every other aggregate now checks whether its source call succeeded,
        via Test-DatasetOk, and emits null if not. Previously these all
        reported 0 off a failed call:
            conditionalAccess.total            -> "no CA policies" vs "no P1"
            devices.compliancePolicies         -> reported 0 off an HTTP 400
            privilegedAccess.eligibleAssignments -> "nobody is eligible" vs "PIM needs P2"
            groups.*, applicationsAndAgents.*, deletedUsers.*, identity.*
        Each section now carries its own *DataAvailable flag.

      - logging.monitoringConfigured was FALSE off a failed call, asserting
        "no alerting configured" when the truth was "could not check". Now
        null, and the probe is no longer -Quiet so the failure appears in
        warnings. LOG-001 reads this field.

      - methodsInUse gains methodsInUsePartial rather than being silently
        emitted as [] while its siblings were null.

    FOR THE ENGINE: null means NOT ASSESSED. A rule whose input is null does
    not fire and does not pass - it reports "not assessed" and the dossier
    says so. Coercing null to 0 reintroduces every defect listed above.

    v0.7.1 - first run with Entra ID P1 licensed, 17 Sep.

      - Get-Prop applied to authMethods and applications. Both had NEVER
        returned data before: authMethods was 403 on every previous run until
        P1 was licensed, and the lab has no app registrations. So neither was
        exercised, neither crashed, and both were skipped in the 15 Sep sweep.
        authMethods then died on defaultMfaMethod, which Graph omits for a
        user with no default method.

        The lesson, stated so it is not relearned: a dataset that has never
        successfully returned data is the MOST likely place for the
        omitted-property bug to hide, not the least. Licensing a tenant, or
        seeding it, turns previously dead code paths live.

      Still unguarded, and deliberately: users, groups and roles. All three
      have returned real data on several runs, so Graph is demonstrably
      sending their selected properties. Revisit if the post-seed run - 24
      users, 6 groups, apps - throws anything.

    v0.7.0 - from reading the output of the first COMPLETE run, 15 Sep 09:59.
    All phases passed; the file itself was wrong in three ways.

      UNKNOWN IS NOT ZERO. The run emitted registrationReportAvailable=false
      beside adminsWithoutMfa=0, on a tenant with three Global Administrators
      and no MFA data at all - and neverSignedIn=3 while the operator had
      signed in a minute earlier. Every aggregate derived from an unreadable
      dataset is now null, with signInDataAvailable / registrationReportAvailable
      alongside. A rule must be able to tell "we looked and found none" from
      "we could not look".

      - Get-Prop now handles IDictionary. $h.key works in PowerShell but
        $h.PSObject.Properties['key'] does not, so Get-Prop was returning the
        default for every one of our own [ordered]@{} objects. Symptom:
        licenceSkus came back as [null].
      - rolesInUse used `Group-Object roleName`, which does not resolve keys on
        an ordered dictionary - all three assignments grouped under "" while
        globalAdministrators (script block) correctly said 3.
      - Warnings gain `kind`: 'error' (could not read) vs 'info' (read fine,
        genuinely empty). In Free mode the message is stripped, so without this
        "no CA policies exist" and "CA policies unreadable" looked identical -
        and they lead to opposite findings.
      - -Status is now passed at every Add-CollectionWarning call site. Six
        warnings in the 09:59 file, four with a null status, in the one mode
        where the status is all the reader gets.

    v0.6.3 - third live smoke test, 15 Sep. All 13 phases passed; the
    aggregator crashed on a tenant with no licences at all.

      - unassignedLicences is summed by hand. Measure-Object -Property against
        the empty subscribedSkus list of an Entra ID Free tenant throws
        "the value of argument 'unassigned' is not valid", which reads like bad
        data and is really empty input.

      A pattern worth noting: all three smoke-test failures were degenerate
      cases - an absent property, an empty probe response, an empty licence
      list. None would have appeared in a tenant with data in it. Running the
      first live test against an almost-empty tenant was worth more than
      running it against a realistic one.

    v0.6.2 - second live smoke test, 15 Sep. Hung at phase 12.

      - Invoke-Graph gains -NoPage, and the three logging calls use it.
        They are readability PROBES (?$top=1), but the paging loop followed
        @odata.nextLink through the ENTIRE directory audit log, one record per
        HTTP request. In the lab that is a hang; on a customer tenant it is
        tens of thousands of requests, certain throttling, and a product that
        looks broken on first contact.
      - monitoringRuleCount renamed to monitoringRuleCountCapped. With $top=5
        on a probe the number answers "any?" and not "how many?", and the old
        name invited a dossier sentence that would have been wrong.

    v0.6.1 - fixes from the FIRST LIVE RUN, 15 Sep (smoke test, lab tenant)

      - Get-Prop helper. Graph OMITS a selected property when its value is
        null rather than returning null, and with StrictMode Latest that makes
        $sp.publisherName throw and kill the run. Crashed at phase 7 on the
        first service principal without a publisher name. All optional reads in
        servicePrincipals, permissionCatalog, conditionalAccess, policies,
        devices and deletedUsers now go through it.
      - roleDefinitions: removed $top, which Graph rejects with 400. This was
        the dangerous one - a failed call left every roleName null, so the
        aggregate privilegedAccess.globalAdministrators silently read 0. A
        tenant with nine Global Admins would have reported none.
      - roleEligibility no longer claims "P2 required" on a 400. 403 is the
        licence answer; 400 is a bad request and asserting a cause from the
        wrong status code is how a dossier gets a fact wrong.
      - policies.telephonyEnabled added - the seeder's Guard 4 signal.

    v0.6.0 changes (rev1 review, 14 Sep, plus the 14 Sep briefing)

      - FREE MODE NO LONGER LEAKS THROUGH `warnings`. The aggregates were
        clean but every warning carried the raw Graph message, and those quote
        the request URI (object IDs on per-object calls), request-ids and
        sometimes a UPN. Free mode now ships dataset + HTTP status only; the
        text stays on the console. Review §2.1.
      - $status is reset on a successful response, so after 429 -> retry ->
        success a caller no longer sees Failed=$false with Status=429. §2.4.
      - NEW: telephonyOnly / adminsTelephonyOnly. Users whose every registered
        method is SMS or voice lose their second factor on 1 Feb 2027, when
        Microsoft stops delivering telephony.
      - NEW: logging.meldplicht - retention (inferred from licence, labelled as
        inferred), alerting, and an explicit null for the Azure-side export
        Graph cannot see. Cbw / RDI focus area 2.

    STILL OPEN, and NOT fixed here because it is Vasil's call:
      - The anonymisation salt is per-run (§2.2). Correct for Free mode; wrong
        for Full mode with monitoring, because the same user gets a different
        entity_ref every month and no finding ever looks closed. Needs a
        per-engagement salt issued by the engine from Key Vault. Touches the
        engine, so it belongs in DECISIONS.md, not in this file.
      - §2.3 throttling detection and §2.5 per-dataset IdFields: Saturday.

    ========================================================================
    Veridan collector. Reads a Microsoft 365 / Entra ID tenant and emits the
    normalized JSON the evidence engine consumes.

    READ-ONLY BY CONSTRUCTION. Every scope is a Read scope.

    ------------------------------------------------------------------------
    v0.5.0 changes (from the 14 Sep review)

    THE BIG ONE - Free mode now emits AGGREGATES, not hashed records.

      v0.4.0 hashed identifiers and shipped all thirteen datasets record by
      record. That is pseudonymisation, not anonymisation, and pseudonymised
      per-person records are still personal data under GDPR - so the claim
      "no identifiers leave the tenant" was not true, and would not have
      survived a Dutch DPO reading the file.

      Free mode now produces counts, distributions and a score. No user
      object, no group object, no service principal object. The client can
      open the file and see that there is nothing in it about anyone.

    Other fixes:
      - list datasets always serialise as arrays, never as {} when count = 1
      - the anonymiser walks PSCustomObject (Graph's actual return type), so
        CA conditions no longer pass through with real GUIDs
      - sentinel values (All, None, Fido2, Graph appId...) are never hashed
      - isPublisherVerified no longer always true
      - Microsoft first-party service principals identified and skipped for
        per-object calls: 600-1200 fewer Graph calls on a real tenant
      - permissionCatalog dataset so permission GUIDs resolve to names
      - Invoke-Graph returns status, so the specific "needs P1 / P2" warnings
        actually fire instead of being dead code
      - Retry-After honoured
      - -ContextScope Process and Disconnect-MgGraph, so no token is left
        cached in the client's profile after a free scan

    ------------------------------------------------------------------------
    MODES

    -Mode Free   delegated, runs on the CLIENT's machine, emits aggregates
                 only. This is the free Zorgplicht Scan.
    -Mode Full   app-only with a certificate, full dataset, for a paid
                 engagement. Encrypted at rest, 30-day retention.

    Both modes run the SAME collection functions. Only the emit stage differs,
    so a finding cannot exist in the paid dossier and be missing from the free
    scan.

    NOTE: Free mode needs the signed-in user to hold at least Global Reader -
    signInActivity and the registration report are not readable otherwise, and
    a non-admin will silently get the degraded fallback.

    ------------------------------------------------------------------------
    SCOPES (all Read, identical in both modes)

      Directory.Read.All, Policy.Read.All, AuditLog.Read.All,
      Application.Read.All, Reports.Read.All, RoleManagement.Read.Directory,
      DeviceManagementConfiguration.Read.All, Organization.Read.All

    ------------------------------------------------------------------------
    EXAMPLES

      .\Invoke-VeridanCollection.ps1 -Mode Free -TenantId <guid>
      .\Invoke-VeridanCollection.ps1 -Mode Full -TenantId <guid> `
          -ClientId <guid> -CertificateThumbprint <thumb> -IncludeScubaGear
      .\Invoke-VeridanCollection.ps1 -Mode Full -TenantId <guid> -Anonymise
#>

[CmdletBinding()]
param(
    [ValidateSet('Free', 'Full')]
    [string] $Mode = 'Free',

    # Now accepted in Free mode too. Without it an MSP admin who is a guest in
    # several tenants gets whichever one happens to be default.
    [string] $TenantId,

    [string] $ClientId,
    [string] $CertificateThumbprint,

    [string] $OutputPath = "$PSScriptRoot\collections",
    [switch] $IncludeScubaGear,

    # Full mode with hashed identifiers - for a demo dossier.
    [switch] $Anonymise,

    # D-007: per-engagement pseudonym key (HMAC-SHA256). Same key -> same
    # pseudonyms across runs. SecureString, e.g.
    #   -AnonymisationSalt (Get-AzKeyVaultSecret -VaultName <v> -Name <client>).SecretValue
    #   -AnonymisationSalt (Read-Host -AsSecureString)
    # Only with -Anonymise. Never written anywhere.
    [SecureString] $AnonymisationSalt,

    [switch] $SkipSignInActivity,
    [int] $InactiveDays = 90,

    # The registration report must cover at least this fraction of the user
    # population before any MFA figure is emitted as a number rather than null.
    #
    # The report lags for hours after a tenant is licensed or an account is
    # created, and a partially populated report produces confident, wrong
    # answers - on 17 Sep it reported "0 users without MFA" from 1 row in a
    # 3-user tenant. 0.95 rather than 1.0 because a single in-flight account
    # should not invalidate a scan of 500 people.
    [ValidateRange(0.0, 1.0)]
    [double] $MinReportCoverage = 0.95,

    # Longest single wait the collector will honour when Graph sends
    # Retry-After. Graph has been seen asking for minutes; a Free-mode scan
    # on a client's laptop cannot sit for an hour on one dataset. Beyond this
    # the dataset is recorded as unreadable (HTTP 429 + code) and the run
    # moves on - unknown, not zero, and not stuck (simulator D23).
    [ValidateRange(1, 3600)]
    [int] $MaxRetryAfterSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$COLLECTOR_VERSION = '0.8.23'
# D-001: this is the version of engine/schema/normalized.schema.json - the
# engine's contract, the engine's numbering. It is NOT this collector's build
# (that is $COLLECTOR_VERSION) and it does not move when the output shape
# changes; a shape change goes to Vasil, who bumps the schema when he takes it.
$SCHEMA_VERSION    = '0.3'   # version of engine/schema/normalized.schema.json, not ours

# =========================================================== infrastructure

$script:Warnings = [System.Collections.Generic.List[object]]::new()

# Datasets whose collection FAILED. Every aggregate derived from one of these
# is emitted as null rather than a count - see the invariant in the header.
$script:FailedDatasets = [System.Collections.Generic.HashSet[string]]::new()

# Fraction of users present in the registration report. Set in main, read by
# the aggregator. $null when it cannot be computed.
$script:ReportCoverage = $null

$script:Timings  = [ordered]@{}
$script:Salt     = [Guid]::NewGuid().ToString('N')
$script:Sha      = [System.Security.Cryptography.SHA256]::Create()   # created once, not per call

# D-007 (v0.8.19): with a per-engagement key the pseudonyms are HMAC-SHA256
# under that key and stable across runs; without one, the per-run salt above
# is used exactly as before.
$script:Hmac = $null
if ($AnonymisationSalt) {
    if (-not $Anonymise) { throw '-AnonymisationSalt only applies with -Anonymise. Refusing rather than silently ignoring it.' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AnonymisationSalt)
    try {
        $keyText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($keyText.Length -lt 16) { throw '-AnonymisationSalt is shorter than 16 characters - too weak for a per-engagement key.' }
        $script:Hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($keyText))
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $keyText = $null
    }
}

# Microsoft's own tenants. Every first-party service principal is owned by one
# of these, so "not our tenant" is NOT the same as "third party".
$script:MicrosoftTenants = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',   # Microsoft Services - the bulk of first-party SPs (100/100 on the lab's first page)
    '72f988bf-86f1-41af-91ab-2d7cd011db47',   # Microsoft corporate tenant
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'    # Microsoft's consumer/MSA app tenant - owns e.g. "Microsoft Graph Command Line Tools"
                                              # (appId 14d82eec-...). Seen live 21 Sep: classified third-party-without-owner,
                                              # produced a false AGT-003 finding in the lab for three days (#35).
)
# Second, list-independent signal: Microsoft's verified-publisher (MPN) id. Publisher
# verification is Microsoft-attested and cannot be self-asserted by a vendor.
$script:MicrosoftVerifiedPublisherId = '5206095'

# Values that look like identifiers but are protocol constants. Hashing them
# destroys the engine's ability to evaluate the rule at all.
$script:Sentinels = @(
    'All','None','GuestsOrExternalUsers','all_users','AllTrusted',
    '00000003-0000-0000-c000-000000000000',   # Microsoft Graph
    '00000002-0000-0ff1-ce00-000000000000',   # Exchange Online
    '00000003-0000-0ff1-ce00-000000000000',   # SharePoint Online
    'Fido2','MicrosoftAuthenticator','Sms','Voice','Email','TemporaryAccessPass',
    'HardwareOath','SoftwareOath','X509Certificate','Password'
)

# Telephony methods, as they appear in methodsRegistered on
# reports/authenticationMethods/userRegistrationDetails.
#
# Microsoft stops DELIVERING these on 1 February 2027; passkeys became the
# registration default on 1 September 2026. Note the wording carefully: after
# February telephony is still possible through a customer's own telecom
# provider, it is just no longer provided by Microsoft. A dossier that says
# "SMS will stop working" is overstating and a client can catch it.
#
# ONE source: rules.yaml telephony_methods (v0.2.1) - exactly these three
# strings, verbatim. A longer list on one side makes the aggregate and the
# IDN-004 record scope disagree at the first extra string, and validate 0.3
# reads the list from rules.yaml. 'mobilePhone' confirmed live 22 Sep; the
# other two are the report's documented values.
$script:TelephonyMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')

# Microsoft stops delivering SMS and voice on 1 February 2027 for everyone
# except Global Administrators and external users, whose date is 1 July 2027
# (learn.microsoft.com, concept-sms-voice-retirement). The schema carries one
# date; the second is for the rules text until Vasil adds a field for it.
$script:TelephonyRetirement           = '2027-02-01'
$script:TelephonyRetirementPrivileged = '2027-07-01'   # not emitted - 0.3 has no field (D-010)

function ConvertTo-VdnUserType {
    # 'guest' -> 'Guest', 'member' -> 'Member', null/other -> unchanged (D-025).
    param($Value)
    switch -Regex ($Value) {
        '^(?i)guest$'  { return 'Guest' }
        '^(?i)member$' { return 'Member' }
        default        { return $Value }
    }
}

function Write-Phase { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Cyan }
function Write-Item  { param([string]$m) Write-Host "   $m" -ForegroundColor DarkGray }

function Add-CollectionWarning {
    <#
        `status` is carried separately from `message` because Free mode ships
        only the status. Graph error messages quote the request URI - which on
        per-object calls contains object IDs - plus request-ids and sometimes a
        UPN. A warning array of raw Graph text made "no identifiers of any
        kind" false for the file even when the aggregates were clean.
    #>
    param(
        [string]$Dataset,
        [string]$Message,
        [int]$Status,
        # 'error'  = we could not read it, so any count derived from it is a lie
        # 'info'   = we read it fine and the answer was empty
        # In Free mode the message is stripped, so without this the file cannot
        # tell "no CA policies exist" apart from "CA policies unreadable" - and
        # those two lead to opposite findings.
        [ValidateSet('error','info')][string]$Kind = 'error',
        # Graph's error.code from the body (e.g. AadPremiumLicenseRequired,
        # Authorization_RequestDenied). Identifier-free, so Free mode ships it.
        [string]$Code
    )
    $script:Warnings.Add([ordered]@{
        dataset = $Dataset
        kind    = $Kind
        status  = $(if ($Status) { $Status } else { $null })
        code    = $(if ($Code) { $Code } else { $null })
        message = $Message
    })
    # 'error' means we could not read it, so every number derived from it is
    # unknown. Recorded here so the aggregator can emit null instead of 0.
    if ($Kind -eq 'error') { [void]$script:FailedDatasets.Add($Dataset) }

    $colour = if ($Kind -eq 'info') { 'DarkGray' } else { 'Yellow' }
    Write-Host "   ! $Dataset : $Message" -ForegroundColor $colour
}

function Get-VdnDenialReason {
    <#
        #47 (v0.8.21). A 403 on these endpoints means "no licence" OR "no
        permission", and only Graph's error.code tells which. Assert a cause
        only when the code names one.
          licence    : AadPremiumLicenseRequired (measured live, PIM, 18 Sep);
                       Authentication_RequestFromNonPremiumTenantOrB2CTenant
                       (Graph's documented answer for sign-in data without a
                       premium licence - not measurable in our lab, which has
                       P1; the simulator carries it).
          permission : Authentication_MSGraphPermissionMissing (measured live
                       28 Sep: directoryAudits without AuditLog.Read.All).
          anything else, including Authorization_RequestDenied (missing role
          and missing consent look the same) and no code at all:
                       "licence or permission", with the code if there is one.
    #>
    param([string] $Code, [int] $Status, [Parameter(Mandatory)][string] $Permission, [string] $Licence = 'Entra ID P1')
    # #48 (v0.8.22): v0.8.21 worded EVERY failure as licence-or-permission,
    # so a 503 on the registration report read "Entra ID P1 or
    # Reports.Read.All missing". Only a 403, or a code that says denial, may
    # name those causes; anything else is reported as what it is.
    # -Licence '' for endpoints that need no licence (directory audits).
    $withCode = $(if ($Code) { " (Graph code $Code)" } else { ' - Graph gave no code' })
    $either   = $(if ($Licence) { "$Licence or $Permission missing" } else { "$Permission missing" })
    if ($Code -match '^(AadPremiumLicenseRequired|Authentication_RequestFromNonPremiumTenantOrB2CTenant)$' -and $Licence) {
        return "$Licence required (Graph code $Code)" }
    if ($Code -eq 'Authentication_MSGraphPermissionMissing') {
        return "$Permission missing (Graph code $Code)" }
    if ($Status -eq 403 -or $Code -eq 'Authorization_RequestDenied') {
        return "$either$withCode" }
    # #52 (v0.8.23): the call sites already say "(HTTP <n>)"; not twice.
    if ($Status -eq 401) {
        return "token rejected$withCode - not a licence or permission answer" }
    $noStatus = $(if (-not $Status) { ' (no HTTP status)' } else { '' })
    return "not a licence or permission answer$noStatus$withCode - transient or service failure"
}

function Get-VdnForbiddenTenantIds {
    <#
        O-9 (v0.8.22). Tenants this installation must never collect from, read
        from forbidden-tenants.txt next to the script. Missing file = empty
        list. Anything that is not a GUID is ignored, so a typo cannot turn
        into "block nothing" silently: the count is printed.
    #>
    param([string] $Path = (Join-Path $PSScriptRoot 'forbidden-tenants.txt'))
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $ids = @(Get-Content -LiteralPath $Path | ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
             Where-Object { $_ -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' } |
             ForEach-Object { $_.ToLowerInvariant() })
    Write-Item "forbidden-tenants.txt: $($ids.Count) tenant(s) refused on this machine"
    return $ids
}

function Assert-VdnTenantAllowed {
    <#
        O-9 (v0.8.22). Runs after Connect-MgGraph and before the first data
        call. Throws - and the main finally disconnects - when the context is
        not the tenant that was asked for, or is on the local refusal list.
    #>
    param([string] $Connected, [string] $Requested, [string[]] $Forbidden = @())
    $c = "$Connected".ToLowerInvariant()
    if (-not $c) { throw 'Refusing to collect: Graph context has no tenant id.' }
    if ($Requested -and $c -ne "$Requested".ToLowerInvariant()) {
        throw "Refusing to collect: asked for tenant $Requested, but the Graph context is $Connected."
    }
    if ($Forbidden -contains $c) {
        throw "Refusing to collect: tenant $Connected is listed in forbidden-tenants.txt on this machine."
    }
}

function Test-DatasetOk {
    <#
        $true only if none of the named datasets recorded an 'error' warning.
        Use it to decide between a count and a null - never to decide between
        a count and zero.
    #>
    param([Parameter(Mandatory)][string[]] $Dataset)
    foreach ($d in $Dataset) { if ($script:FailedDatasets.Contains($d)) { return $false } }
    return $true
}

function Protect-Id {
    param([string]$Value)
    if (-not $Value) { return $null }
    $h = if ($script:Hmac) { $script:Hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) }
         else              { $script:Sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$script:Salt|$Value")) }
    ($h | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-Prop {
    <#
        Safe property read off a Graph response object.

        WHY THIS EXISTS. Graph does not return a selected property at all when
        its value is null on that object - it omits the key rather than sending
        null. Combined with Set-StrictMode -Version Latest, a plain $sp.foo then
        throws "The property 'foo' cannot be found on this object" and kills the
        whole run on the first service principal that happens to have no
        publisher name.

        Found by the first live smoke test, 15 Sep, at phase 7.

        Do NOT solve this by relaxing StrictMode. StrictMode is what stops a
        typo'd property name from silently reading as $null, and a silent $null
        in this script means a finding quietly reports zero - which reads as
        good news. Guard the access instead.
    #>
    param($Object, [Parameter(Mandatory)][string] $Name, $Default = $null)

    if ($null -eq $Object) { return $Default }

    # Dictionaries FIRST. $hashtable.key works in PowerShell, but
    # $hashtable.PSObject.Properties['key'] does NOT - that enumerates the
    # dictionary's own .NET members (Count, Keys, Values), never its keys.
    # Without this branch, Get-Prop silently returns $default for every one of
    # our own [ordered]@{} objects. That is how licenceSkus came back as
    # [null] in the 09:59 smoke test.
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }

    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

function Get-GraphErrorStatus {
    <#
        Best-effort HTTP status out of a Graph SDK error record.

        DEFENCE IN DEPTH, NOT A BUG FIX. Stated accurately because the first
        version of this comment overstated it.

        Review item 2.3 asked whether the retry branch was dead code, because
        it read one path only: $_.Exception.Response.StatusCode.value__.
        Tested live on 17 Sep with a deliberately malformed filter, and the
        answer is NO - a real HTTP error arrives as
        Microsoft.Graph.PowerShell.Authentication.Helpers.HttpResponseException,
        which does carry .Response, and the status resolved to 400 first try.
        429 arrives the same way, so throttling retries do work.

        What does NOT carry a response is Microsoft.Graph.PowerShell.
        AuthenticationException - a pre-flight authorisation failure, raised
        before any request is sent. That class must never be retried anyway,
        so the original code was right about the case that matters.

        This function exists so that a future SDK change to the exception
        shape degrades into "read it from the text" rather than into "no
        retries at all". Four routes, cheapest first. $null only when nothing
        can be determined.
    #>
    param([Parameter(Mandatory)] $ErrorRecord)

    # 1. Classic HttpResponseMessage - the original assumption.
    try {
        $v = $ErrorRecord.Exception.Response.StatusCode.value__
        if ($v) { return [int]$v }
    } catch { }

    # 2. Same property, but carrying an HttpStatusCode enum rather than an int.
    try {
        $v = $ErrorRecord.Exception.Response.StatusCode
        if ($v -is [System.Net.HttpStatusCode]) { return [int]$v }
    } catch { }

    # 3. SDK exception types that expose the code directly.
    foreach ($name in 'ResponseStatusCode', 'StatusCode', 'HttpStatusCode') {
        try {
            $p = $ErrorRecord.Exception.PSObject.Properties[$name]
            if ($p -and $p.Value) { return [int]$p.Value }
        } catch { }
    }

    # 4. Read it out of the text. Ugly, and the only option when the exception
    #    carries no response object - which is the case that broke retries.
    $txt = Get-ErrorText $ErrorRecord
    if ($txt -match 'TooManyRequests|Too Many Requests|\b429\b') { return 429 }
    if ($txt -match 'ServiceUnavailable|\b503\b')                { return 503 }
    if ($txt -match 'GatewayTimeout|\b504\b')                    { return 504 }
    if ($txt -match 'BadGateway|\b502\b')                        { return 502 }
    if ($txt -match 'InternalServerError|\b500\b')               { return 500 }
    if ($txt -match 'Forbidden|\b403\b')                         { return 403 }
    if ($txt -match 'Unauthorized|\b401\b')                      { return 401 }
    if ($txt -match 'BadRequest|Bad Request|\b400\b')            { return 400 }
    if ($txt -match 'NotFound|Not Found|\b404\b')                { return 404 }

    return $null
}

function Get-GraphErrorCode {
    <#
        Graph's own error CODE out of the response body - the one thing that
        actually says WHY a call failed. The HTTP status alone does not:
        captured live on 18 Sep, the lab tenant answers roleEligibilitySchedules
        with HTTP 400 and body {"error":{"code":"AadPremiumLicenseRequired",...}}.
        Reading only the status forced v0.8.5 to write "bad request - NOT
        necessarily a licence problem" when the body said, in so many words,
        that it was exactly a licence problem.

        The SDK puts the body in $_.ErrorDetails.Message; a raw exception may
        carry it in .Exception.Message. Both are searched. Codes are plain
        identifiers (no URIs, no object IDs, no UPNs), so a code is safe to
        ship in Free mode where the message is not.
    #>
    param([Parameter(Mandatory)] $ErrorRecord)
    $txt = Get-ErrorText $ErrorRecord
    if ($txt -match '"code"\s*:\s*"([A-Za-z0-9_.\-]{1,80})"') { return $Matches[1] }
    return $null
}

function Get-ErrorText {
    <#
        ErrorDetails is NULL on any exception the SDK did not raise from an HTTP
        response (AuthenticationException, the shim, a plain throw). Under
        StrictMode $null.Message is a terminating error, so the first v0.8.8
        crashed the whole run on the first non-HTTP failure (simulator P14/P15).
        The same expression sat in Get-GraphErrorStatus route 4 since v0.8.3 -
        latent, because routes 1-3 always answered first.
    #>
    param([Parameter(Mandatory)] $ErrorRecord)
    $parts = [System.Collections.Generic.List[string]]::new()
    try { $ed = $ErrorRecord.ErrorDetails; if ($null -ne $ed) { $parts.Add([string]$ed.Message) } } catch { }
    try { $ex = $ErrorRecord.Exception;    if ($null -ne $ex) { $parts.Add([string]$ex.Message) } } catch { }
    return ($parts -join ' ')
}

function Invoke-Graph {
    <#
        Paged Graph GET.

        Returns a RESULT OBJECT, not a bare list, so callers can branch on
        status. In v0.4.0 this swallowed everything and returned empty, which
        made every try/catch around it dead code and meant the specific
        "requires P1 / P2" warnings never fired.

        .Items   the collected rows
        .Status  last HTTP status, $null on success
        .Failed  $true if the call could not be completed
    #>
    param(
        [Parameter(Mandatory)][string] $Uri,
        [ValidateSet('v1.0','beta')][string] $Version = 'v1.0',
        [string] $Dataset = 'unknown',
        [int] $MaxRetries = 5,
        [switch] $Quiet,         # do not auto-log a warning; caller will

        # PROBE MODE. Take the first page and stop.
        #
        # Without this, a call like auditLogs/directoryAudits?$top=1 - intended
        # to ask "can I read this at all?" - follows @odata.nextLink through the
        # ENTIRE audit log, one record per HTTP request. Found live on 15 Sep
        # when the smoke test hung at phase 12. On a customer tenant that is
        # tens of thousands of requests, guaranteed throttling, and a collector
        # that looks broken.
        [switch] $NoPage
    )

    $all = [System.Collections.Generic.List[object]]::new()
    $next = "https://graph.microsoft.com/$Version/$($Uri.TrimStart('/'))"
    $attempt = 0
    $status = $null
    $failed = $false
    $message = $null
    $code    = $null

    while ($next) {
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
            $attempt = 0
            # Reset on success. Previously $status was only ever written in the
            # catch block, so after 429 -> retry -> success the caller saw
            # Failed = $false with Status = 429 still attached.
            $status = $null

            if ($resp.PSObject.Properties.Name -contains 'value') {
                foreach ($v in $resp.value) { $all.Add($v) }
                $next = if (-not $NoPage -and $resp.PSObject.Properties.Name -contains '@odata.nextLink') { $resp.'@odata.nextLink' } else { $null }
            } else {
                $all.Add($resp); $next = $null
            }
        }
        catch {
            $message = $_.Exception.Message
            $status  = Get-GraphErrorStatus $_
            $code    = Get-GraphErrorCode $_

            if ($status -in 429, 500, 502, 503, 504 -and $attempt -lt $MaxRetries) {
                $attempt++
                # Honour Retry-After when Graph sends it; blind backoff otherwise.
                $wait = $null
                try {
                    $ra = $_.Exception.Response.Headers.RetryAfter
                    if ($ra -and $ra.Delta) { $wait = [int]$ra.Delta.TotalSeconds }
                } catch { }
                if (-not $wait) { $wait = [math]::Min(60, [math]::Pow(2, $attempt)) }
                if ($wait -gt $MaxRetryAfterSeconds) {
                    # Do not sleep for a quarter of an hour on one call. Record
                    # the refusal honestly and let the aggregator null the
                    # dataset. The message carries the requested wait.
                    $message = "Graph asked to wait ${wait}s (Retry-After) on $Dataset - beyond the ${MaxRetryAfterSeconds}s budget; dataset recorded as unreadable. $message"
                    Write-Item "throttled ($status), Retry-After ${wait}s exceeds budget ${MaxRetryAfterSeconds}s - giving up on this dataset"
                } else {
                    Write-Item "throttled ($status), retry $attempt in ${wait}s"
                    Start-Sleep -Seconds $wait
                    continue
                }
            }

            $failed = $true
            if (-not $Quiet) { Add-CollectionWarning -Dataset $Dataset -Message $message -Status $status -Code $code }
            $next = $null
        }
    }

    return [pscustomobject]@{ Items = @($all); Status = $status; Failed = $failed; Message = $message; Code = $code }
}

function Measure-Phase {
    param([string] $Name, [scriptblock] $Body)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = & $Body
    $sw.Stop()
    $script:Timings[$Name] = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-Item ("{0} in {1}s" -f $Name, $script:Timings[$Name])
    return $result
}

# ================================================================= 1. TENANT

function Get-VdnTenant {
    Write-Phase '1. Tenant'

    $orgR  = Invoke-Graph -Uri 'organization' -Dataset 'tenant'
    $skusR = Invoke-Graph -Uri 'subscribedSkus' -Dataset 'licences'

    $secDefaults = $null
    $sdR = Invoke-Graph -Uri 'policies/identitySecurityDefaultsEnforcementPolicy' -Dataset 'tenant' -Quiet
    if ($sdR.Failed) {
        Add-CollectionWarning -Dataset 'tenant' -Status $sdR.Status -Code $sdR.Code -Message 'security defaults state unreadable'
    } else {
        $secDefaults = [bool]($sdR.Items | Select-Object -First 1).isEnabled
    }

    # /organization can fail like any other call (simulator D04: HTTP 503).
    # $o is then $null and, under StrictMode, $o.id is a terminating error -
    # the run died in phase 1 with nothing written. The tenant id itself is
    # still known: it is the one the session authenticated to.
    $o = $orgR.Items | Select-Object -First 1
    $ctxTenant = $null
    try { $ctxTenant = (Get-MgContext).TenantId } catch { }

    [ordered]@{
        tenantId                   = $(if ($o) { Get-Prop $o 'id' } elseif ($TenantId) { $TenantId } else { $ctxTenant })
        organizationDataAvailable  = (-not $orgR.Failed)
        displayName                = (Get-Prop $o 'displayName')
        createdDateTime            = (Get-Prop $o 'createdDateTime')
        countryLetterCode          = (Get-Prop $o 'countryLetterCode')
        technicalNotificationMails = @(Get-Prop $o 'technicalNotificationMails' @())
        verifiedDomains            = @(Get-Prop $o 'verifiedDomains' @() | ForEach-Object {
                                        [ordered]@{ name=(Get-Prop $_ 'name'); isDefault=(Get-Prop $_ 'isDefault'); isInitial=(Get-Prop $_ 'isInitial'); type=(Get-Prop $_ 'type') } })
        onPremisesSyncEnabled      = (Get-Prop $o 'onPremisesSyncEnabled')
        securityDefaultsEnabled    = $secDefaults
        licences                   = @($skusR.Items | ForEach-Object {
                                        $pu = Get-Prop $_ 'prepaidUnits'
                                        $en = Get-Prop $pu 'enabled'; $co = Get-Prop $_ 'consumedUnits'
                                        # consumedUnits CAN exceed prepaidUnits.enabled (a lapsed or
                                        # reduced subscription keeps its assignments). enabled - consumed
                                        # then goes negative, and the schema's count type refuses the
                                        # file. Unassigned is clamped at 0; the excess is its own signal.
                                        [ordered]@{
                                            skuId = (Get-Prop $_ 'skuId'); skuPartNumber = (Get-Prop $_ 'skuPartNumber')
                                            enabled = $en; consumed = $co
                                            unassigned   = $(if ($null -ne $en -and $null -ne $co) { [math]::Max(0, $en - $co) } else { $null })
                                            overAssigned = $(if ($null -ne $en -and $null -ne $co) { [math]::Max(0, $co - $en) } else { $null })
                                            servicePlans = @(Get-Prop $_ 'servicePlans' @() | ForEach-Object { Get-Prop $_ 'servicePlanName' })
                                        } })
    }
}

# ================================================================== 2. USERS

function Get-VdnUsers {
    Write-Phase '2. Users'

    $select = @('id','userPrincipalName','displayName','givenName','surname','mail',
        'accountEnabled','userType','createdDateTime','department','jobTitle',
        'companyName','employeeId','usageLocation','assignedLicenses',
        'onPremisesSyncEnabled','onPremisesImmutableId','externalUserState',
        'creationType','passwordPolicies','lastPasswordChangeDateTime','proxyAddresses')
    if (-not $SkipSignInActivity) { $select += 'signInActivity' }

    # [VERIFY] $top=999 with $select=signInActivity has had page-size limits.
    # If the first call 400s, drop to 120.
    $top = if ($SkipSignInActivity) { 999 } else { 120 }
    $r = Invoke-Graph -Uri "users?`$select=$($select -join ',')&`$top=$top" -Dataset 'users' -Quiet

    # Tracked so the aggregates can say "unknown" instead of inventing a number.
    # Without sign-in data every user looks never-signed-in, which is not a
    # cautious default - it is a false positive on every account in the tenant.
    $script:SignInActivityAvailable = (-not $SkipSignInActivity)
    if ($SkipSignInActivity) {
        # #44: unknown must say WHY. Without this the file reads like a tenant
        # without P1, and the dossier's reason ("needs P1") would be false.
        Add-CollectionWarning -Dataset 'usersSignInActivity' -Kind 'info' -Code 'SkippedByOperator' -Message (
            'signInActivity not requested (-SkipSignInActivity). Sign-in figures are null by operator choice, not for lack of licence or permission.')
    }

    # Fall back ONLY on the answers that mean "you may not read signInActivity":
    # 403 (no P1 / no directory role) or a 400 whose code says the property is
    # not permitted. Any other failure - a 503 on page 2, a 429 that outlived
    # its retries, a 401 - is a failed users call and must be filed as one.
    # v0.8.9 and earlier fell back on ANY failure, so a transient 503 produced
    # a warning claiming "Entra ID P1 required" and then re-read the whole
    # directory a second time (simulator D16: 132 s and a false licence story).
    $signInDenied = $r.Failed -and -not $SkipSignInActivity -and (
        $r.Status -eq 403 -or ($r.Status -eq 400 -and "$($r.Code)" -match 'Request_UnsupportedQuery|Authorization_RequestDenied|BadRequest'))

    if ($signInDenied) {
        # Dataset name is deliberately NOT 'users'. Filing this under 'users'
        # marked the whole dataset failed, so on every tenant without P1 the
        # fallback succeeded and the aggregator still emitted usersTotal /
        # usersEnabled / guests / ... as null - and validate.py rejected the
        # file (those are non-nullable integers in the schema). Found by the
        # simulator on T01 and T03, 18 Sep. Same pattern as authMethodsCoverage:
        # the DEGRADATION gets its own name; the dataset itself is fine.
        # #47: code and cause from THIS response - $r is reassigned below.
        Add-CollectionWarning -Dataset 'usersSignInActivity' -Status $r.Status -Code $r.Code -Message (
            "signInActivity unavailable (HTTP $($r.Status)) - $(Get-VdnDenialReason -Code $r.Code -Status $r.Status -Permission 'AuditLog.Read.All'). Retrying without it.")
        $script:SignInActivityAvailable = $false
        $select = $select | Where-Object { $_ -ne 'signInActivity' }
        $r = Invoke-Graph -Uri "users?`$select=$($select -join ',')&`$top=999" -Dataset 'users'
    } elseif ($r.Failed) {
        Add-CollectionWarning -Dataset 'users' -Status $r.Status -Code $r.Code -Message $r.Message
    }

    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)

    return @($r.Items | ForEach-Object {
        # signInActivity is an object, and lastSignInDateTime inside it is
        # itself omitted for an account that has never signed in - so this
        # needs the guarded read at both levels.
        $last    = Get-Prop (Get-Prop $_ 'signInActivity') 'lastSignInDateTime'
        $lastDt  = $(if ($last) { [datetime]$last } else { $null })
        $rawCreated = Get-Prop $_ 'createdDateTime'
        $created = $(if ($rawCreated) { [datetime]$rawCreated } else { $null })

        # Guarded ahead of the POST-SEED run, not because this has failed.
        #
        # Every collection so far has read exactly three MEMBER accounts. The
        # seeded lab holds 24 users including six GUESTS and four disabled
        # ones, and a guest object is not shaped like a member: mail,
        # externalUserState, creationType and givenName all behave differently
        # on an invited identity.
        #
        # The post-seed collection IS the golden-diff run. A crash there costs
        # the seeded state, and reseeding needs a full teardown with -Purge
        # plus the 30-day UPN window. Cheap insurance against an expensive stop.
        $licences = @(Get-Prop $_ 'assignedLicenses' @())

        [ordered]@{
            id = (Get-Prop $_ 'id')
            userPrincipalName = (Get-Prop $_ 'userPrincipalName')
            displayName = (Get-Prop $_ 'displayName')
            givenName = (Get-Prop $_ 'givenName')
            surname = (Get-Prop $_ 'surname')
            mail = (Get-Prop $_ 'mail')
            accountEnabled = (Get-Prop $_ 'accountEnabled')
            userType = (Get-Prop $_ 'userType')
            createdDateTime = (Get-Prop $_ 'createdDateTime')
            ageDays = $(if ($created) { [int]((Get-Date).ToUniversalTime() - $created).TotalDays } else { $null })
            department = (Get-Prop $_ 'department')
            jobTitle = (Get-Prop $_ 'jobTitle')
            companyName = (Get-Prop $_ 'companyName')
            employeeId = (Get-Prop $_ 'employeeId')
            usageLocation = (Get-Prop $_ 'usageLocation')
            licenceCount = $licences.Count
            isLicensed = ($licences.Count -gt 0)
            syncedFromOnPrem = [bool](Get-Prop $_ 'onPremisesSyncEnabled')
            hasImmutableId = [bool](Get-Prop $_ 'onPremisesImmutableId')
            externalUserState = (Get-Prop $_ 'externalUserState')
            creationType = (Get-Prop $_ 'creationType')
            passwordPolicies = (Get-Prop $_ 'passwordPolicies')
            lastPasswordChange = (Get-Prop $_ 'lastPasswordChangeDateTime')
            lastSignInDateTime = $last
            # #42: only when signInActivity was actually READ. Without it $lastDt
            # is null for everyone and both flags said true for the whole tenant.
            neverSignedIn = $(if ($script:SignInActivityAvailable) { $null -eq $lastDt } else { $null })
            # RAW signal only. Whether "inactive" exempts accounts younger than
            # the threshold is a RULE decision and belongs in rules.yaml, not here.
            inactiveByLastSignIn = $(if ($script:SignInActivityAvailable) { $null -eq $lastDt -or $lastDt -lt $cutoff } else { $null })
            proxyAddressCount = @(Get-Prop $_ 'proxyAddresses' @()).Count
        }
    })
}

# ========================================================= 3. AUTH METHODS

function Get-VdnAuthMethods {
    Write-Phase '3. Authentication method registration'

    $r = Invoke-Graph -Uri 'reports/authenticationMethods/userRegistrationDetails?$top=999' -Dataset 'authMethods' -Quiet
    if ($r.Failed) {
        Add-CollectionWarning -Dataset 'authMethods' -Status $r.Status -Code $r.Code -Message (
            "registration details unavailable (HTTP $($r.Status)) - $(Get-VdnDenialReason -Code $r.Code -Status $r.Status -Permission 'Reports.Read.All'). isAdmin lives here, so admin-without-MFA becomes UNKNOWN, not zero.")
        return @()
    }

    # Every read guarded. This dataset had returned 403 on every run until P1
    # was licensed on 17 Sep, so it was never exercised and never crashed -
    # which is exactly why it was missed in the 15 Sep sweep. It then died on
    # defaultMfaMethod, which Graph omits for a user with no default method.
    #
    # A dataset that has never successfully returned data is the most likely
    # place for this bug to be hiding, not the least.
    return @($r.Items | ForEach-Object {
        [ordered]@{
            id                    = (Get-Prop $_ 'id')
            userPrincipalName     = (Get-Prop $_ 'userPrincipalName')
            userDisplayName       = (Get-Prop $_ 'userDisplayName')
            isAdmin               = (Get-Prop $_ 'isAdmin')
            isMfaRegistered       = (Get-Prop $_ 'isMfaRegistered')
            isMfaCapable          = (Get-Prop $_ 'isMfaCapable')
            isPasswordlessCapable = (Get-Prop $_ 'isPasswordlessCapable')
            isSsprRegistered      = (Get-Prop $_ 'isSsprRegistered')
            isSsprEnabled         = (Get-Prop $_ 'isSsprEnabled')
            isSsprCapable         = (Get-Prop $_ 'isSsprCapable')
            methodsRegistered     = @(Get-Prop $_ 'methodsRegistered' @())
            defaultMfaMethod      = (Get-Prop $_ 'defaultMfaMethod')
            # D-025: the report says "guest" / "member" in lower case (measured
            # 22 Sep); the schema enum and the users dataset say Guest / Member.
            # Anything else (null on a legacy account) passes through unchanged.
            userType              = (ConvertTo-VdnUserType (Get-Prop $_ 'userType'))
            lastUpdatedDateTime   = (Get-Prop $_ 'lastUpdatedDateTime')
        }
    })
}

# ================================================================= 4. GROUPS

function Get-VdnGroups {
    Write-Phase '4. Groups'

    $gR = Invoke-Graph -Dataset 'groups' -Uri ("groups?`$select=" + (@(
        'id','displayName','description','mail','mailEnabled','securityEnabled','groupTypes',
        'visibility','createdDateTime','membershipRule','membershipRuleProcessingState',
        'isAssignableToRole','onPremisesSyncEnabled','expirationDateTime','resourceProvisioningOptions'
    ) -join ',') + "&`$top=999")

    return @(foreach ($g in $gR.Items) {
        # directoryObject does not carry userPrincipalName / userType; take the
        # type from @odata.type, which is always present.
        #
        # RESULT OBJECTS, not bare .Items. A failed members or owners call
        # returns empty, and an empty list read as "no members / no owners"
        # turns an unanswered question into a FINDING (isEmpty, hasNoOwner).
        # These per-object failures land under 'groupMembers'/'groupOwners' in
        # warnings - dataset names no availability flag ever read. So the
        # failure was recorded and still invisible: defect #5, one level down.
        # When the call failed, every field derived from it is null.
        # beta, NOT v1.0: v1.0 /members hides servicePrincipal members (#39,
        # measured 22 Sep on the B9 probe group; beta returns them, as does the
        # v1.0 type cast). An SP-only group on v1.0 reads as empty - a false
        # finding. Owners on beta by the same logic (unverified symmetry).
        $memR = Invoke-Graph -Version beta -Uri "groups/$($g.id)/members?`$select=id,displayName&`$top=999" -Dataset 'groupMembers'
        $ownR = Invoke-Graph -Version beta -Uri "groups/$($g.id)/owners?`$select=id,displayName&`$top=999" -Dataset 'groupOwners'
        $mem = $memR.Items
        $own = $ownR.Items
        $memKnown = -not $memR.Failed
        $ownKnown = -not $ownR.Failed

        $users   = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' })
        $nested  = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' })
        $sps     = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' })
        $devices = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' })

        # Guarded since v0.8.7. The lab's three groups are all Unified with a
        # mail address, so "Graph returns explicit nulls for groups" was only
        # ever observed on groups that had few nulls to omit. Under the
        # collector's own §3.7 belief this block crashed on $g.mail (simulator
        # D13/P47, 18 Sep). Get-Prop costs nothing and removes the bet.
        # #43: null, not [], when the call failed. Assigned through variables on
        # purpose - $(if ...) inside the literal would unroll a one-element list
        # into a scalar and an empty list into $null, which is the very bug.
        $memberIdList = $null; $nestedIdList = $null; $ownerIdList = $null
        if ($memKnown) { $memberIdList = @($users | ForEach-Object { $_.id }); $nestedIdList = @($nested | ForEach-Object { $_.id }) }
        if ($ownKnown) { $ownerIdList  = @($own | ForEach-Object { $_.id }) }

        $gt = @(Get-Prop $g 'groupTypes' @())
        [ordered]@{
            id = $g.id; displayName = (Get-Prop $g 'displayName'); description = (Get-Prop $g 'description')
            mail = (Get-Prop $g 'mail'); mailEnabled = (Get-Prop $g 'mailEnabled'); securityEnabled = (Get-Prop $g 'securityEnabled')
            groupTypes = $gt
            isUnified = ($gt -contains 'Unified')
            isDynamic = ($gt -contains 'DynamicMembership')
            membershipRule = (Get-Prop $g 'membershipRule'); visibility = (Get-Prop $g 'visibility')
            isAssignableToRole = (Get-Prop $g 'isAssignableToRole')
            syncedFromOnPrem = [bool](Get-Prop $g 'onPremisesSyncEnabled')
            hasTeam = (@(Get-Prop $g 'resourceProvisioningOptions' @()) -contains 'Team')
            createdDateTime = (Get-Prop $g 'createdDateTime'); expirationDateTime = (Get-Prop $g 'expirationDateTime')
            memberDataKnown = $memKnown
            ownerDataKnown  = $ownKnown
            memberUserCount = $(if ($memKnown) { $users.Count } else { $null })
            memberGroupCount = $(if ($memKnown) { $nested.Count } else { $null })
            memberSpCount = $(if ($memKnown) { $sps.Count } else { $null })
            memberDeviceCount = $(if ($memKnown) { $devices.Count } else { $null })
            ownerCount = $(if ($ownKnown) { @($own).Count } else { $null })
            isEmpty = $(if ($memKnown) { @($mem).Count -eq 0 } else { $null })
            hasNoOwner = $(if ($ownKnown) { @($own).Count -eq 0 } else { $null })
            memberIds = $memberIdList
            nestedGroupIds = $nestedIdList
            ownerIds = $ownerIdList
        }
    })
}

# ================================================================== 5. ROLES

function Get-VdnRoles {
    Write-Phase '5. Directory roles and PIM'

    # NO $top HERE. roleDefinitions rejects it with 400 - found live, 15 Sep.
    # This mattered more than it looks: when this call fails, $defMap is empty,
    # every roleName comes back $null, and the aggregate
    # privilegedAccess.globalAdministrators silently becomes 0. A tenant with
    # nine Global Admins would have reported none, and nobody would have
    # questioned a clean number.
    # $select trims the payload: full definitions carry rolePermissions blobs
    # this function never reads. ($select is accepted here; $top is not.)
    $dR = Invoke-Graph -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName' -Dataset 'roleDefinitions' -Quiet
    if ($dR.Failed) {
        Add-CollectionWarning -Dataset 'roleDefinitions' -Status $dR.Status -Code $dR.Code -Message (
            "role definitions unreadable (HTTP $($dR.Status)). Role NAMES will be null and any rule matching on roleName cannot fire. Treat this run's privileged-access section as unusable.")
    }
    $defMap = @{}
    foreach ($d in $dR.Items) {
        $id = Get-Prop $d 'id'
        if ($id) { $defMap[$id] = (Get-Prop $d 'displayName') }
    }

    $active = (Invoke-Graph -Uri 'roleManagement/directory/roleAssignments?$expand=principal&$top=999' -Dataset 'roleAssignments').Items

    $eR = Invoke-Graph -Version beta -Dataset 'roleEligibility' -Quiet `
          -Uri 'roleManagement/directory/roleEligibilitySchedules?$expand=principal&$top=999'
    if ($eR.Failed) {
        # The BODY says why, the status does not. Captured live on 18 Sep: the
        # lab (no P2) answers HTTP 400 with code AadPremiumLicenseRequired. So
        # the licence verdict comes from the code; the status-only fallbacks
        # below stay deliberately non-committal.
        $why = if ($eR.Code -eq 'AadPremiumLicenseRequired') {
                   "Entra ID P2 / Governance licence required (Graph code $($eR.Code))"
               } elseif ($eR.Code -eq 'Authorization_RequestDenied') {
                   "permission denied (Graph code $($eR.Code)) - RoleEligibilitySchedule.Read.Directory missing"
               } else {
                   switch ($eR.Status) {
                       403     { 'forbidden - licence or permission; Graph gave no code' }
                       400     { 'bad request without a recognised code - PIM not provisioned or query shape wrong. NOT necessarily a licence problem' }
                       default { 'see console for detail' }
                   }
               }
        Add-CollectionWarning -Dataset 'roleEligibility' -Status $eR.Status -Code $eR.Code -Message (
            "PIM eligibility unavailable (HTTP $($eR.Status)) - $why")
    }

    $shape = {
        param($a, $kind)
        $p = Get-Prop $a 'principal'
        $ptype = if ($p) { ((Get-Prop $p '@odata.type') -replace '#microsoft.graph.','') } else { $null }
        $rdid = Get-Prop $a 'roleDefinitionId'
        [ordered]@{
            assignmentType = $kind
            roleDefinitionId = $rdid
            roleName = $(if ($rdid -and $defMap.ContainsKey($rdid)) { $defMap[$rdid] } else { $null })
            principalId = (Get-Prop $a 'principalId')
            principalType = $ptype
            principalName = if ($p) { Get-Prop $p 'displayName' } else { $null }
            principalUpn = if ($p) { Get-Prop $p 'userPrincipalName' } else { $null }
            # NOTE: group principals are NOT expanded to their members. A rule
            # counting Global Admins from this dataset will undercount where
            # role-assignable groups are used. Use authMethods.isAdmin as the
            # cross-check.
            isGroupAssignment = ($ptype -eq 'group')
            directoryScopeId = (Get-Prop $a 'directoryScopeId')
        }
    }

    $rows = @()
    foreach ($a in $active)    { $rows += & $shape $a 'permanent' }
    foreach ($a in $eR.Items)  { $rows += & $shape $a 'eligible'  }
    return @($rows)
}

# =========================================================== 6. APPLICATIONS

function Get-VdnApplications {
    Write-Phase '6. Application registrations'

    $aR = Invoke-Graph -Dataset 'applications' -Uri ("applications?`$select=" + (@(
        'id','appId','displayName','createdDateTime','signInAudience',
        'passwordCredentials','keyCredentials','requiredResourceAccess','web','notes'
    ) -join ',') + "&`$top=999")

    $now = (Get-Date).ToUniversalTime()

    return @(foreach ($a in $aR.Items) {
        # Result object, not bare .Items - a failed owners call must yield
        # hasNoOwner = null, not a fabricated "no owner" finding. Same fix as
        # groups; see the comment there.
        $ownR = Invoke-Graph -Uri "applications/$($a.id)/owners?`$select=id,displayName&`$top=999" -Dataset 'appOwners'
        $own = $ownR.Items
        $ownKnown = -not $ownR.Failed

        # Guarded for the same reason as authMethods: the lab has zero app
        # registrations, so this has never been exercised either. It will be
        # the moment the seeder creates its orphan and high-privilege apps.
        # passwordCredentials, keyCredentials and requiredResourceAccess are
        # all omitted by Graph when empty.
        $shapeCred = {
            param($c)
            $end = Get-Prop $c 'endDateTime'
            [ordered]@{
                displayName  = (Get-Prop $c 'displayName')
                endDateTime  = $end
                expired      = $(if ($end) { ([datetime]$end -lt $now) } else { $null })
                daysToExpiry = $(if ($end) { [int](([datetime]$end) - $now).TotalDays } else { $null })
            }
        }

        $secrets = @(Get-Prop $a 'passwordCredentials' @() | ForEach-Object { & $shapeCred $_ })
        $certs   = @(Get-Prop $a 'keyCredentials'      @() | ForEach-Object { & $shapeCred $_ })
        $audience = Get-Prop $a 'signInAudience'
        $web      = Get-Prop $a 'web'

        [ordered]@{
            id = (Get-Prop $a 'id'); appId = (Get-Prop $a 'appId')
            displayName = (Get-Prop $a 'displayName')
            createdDateTime = (Get-Prop $a 'createdDateTime'); signInAudience = $audience
            isMultiTenant = ($audience -and $audience -ne 'AzureADMyOrg')
            ownerDataKnown = $ownKnown
            ownerCount = $(if ($ownKnown) { @($own).Count } else { $null })
            hasNoOwner = $(if ($ownKnown) { @($own).Count -eq 0 } else { $null })
            secretCount = $secrets.Count; certCount = $certs.Count
            secrets = $secrets; certificates = $certs
            hasExpiredCredential = (@(@($secrets) + @($certs) | Where-Object { $_.expired -eq $true }).Count -gt 0)
            redirectUris = @(Get-Prop $web 'redirectUris' @())
            requestedPermissions = @(Get-Prop $a 'requiredResourceAccess' @() | ForEach-Object {
                [ordered]@{
                    resourceAppId = (Get-Prop $_ 'resourceAppId')
                    scopes = @(Get-Prop $_ 'resourceAccess' @() | ForEach-Object {
                        [ordered]@{ id = (Get-Prop $_ 'id'); type = (Get-Prop $_ 'type') } })
                } })
        }
    })
}

# ====================================================== 7. SERVICE PRINCIPALS

function Get-VdnServicePrincipals {
    param([string] $TenantOrgId)

    Write-Phase '7. Service principals, consent and agents'

    $spR = Invoke-Graph -Dataset 'servicePrincipals' -Uri ("servicePrincipals?`$select=" + (@(
        'id','appId','displayName','servicePrincipalType','accountEnabled',
        'appOwnerOrganizationId','signInAudience','tags','createdDateTime',
        'publisherName','verifiedPublisher','homepage','notes'
    ) -join ',') + "&`$top=999")

    $grants = (Invoke-Graph -Uri 'oauth2PermissionGrants?$top=999' -Dataset 'oauth2Grants').Items
    $grantsBySp = @{}
    foreach ($g in $grants) {
        $cid = Get-Prop $g 'clientId'
        if (-not $cid) { continue }
        if (-not $grantsBySp.ContainsKey($cid)) { $grantsBySp[$cid] = @() }
        $grantsBySp[$cid] += $g
    }

    $agentHints = @('Copilot','Bot','Agent','PowerVirtualAgents','Copilot Studio','AI Builder')
    $skipped = 0

    $out = @(foreach ($sp in $spR.Items) {

        $ownerOrg = Get-Prop $sp 'appOwnerOrganizationId'
        $spName   = Get-Prop $sp 'displayName'
        $spType   = Get-Prop $sp 'servicePrincipalType'

        $vpEarly = Get-Prop $sp 'verifiedPublisher'
        $isFirstParty = ($ownerOrg -in $script:MicrosoftTenants) -or
                        ((Get-Prop $vpEarly 'verifiedPublisherId') -eq $script:MicrosoftVerifiedPublisherId)
        $isThirdParty = ($ownerOrg -and
                         $ownerOrg -notin $script:MicrosoftTenants -and
                         $ownerOrg -ne $TenantOrgId)

        # A Business Premium tenant carries 300-600 service principals, nearly
        # all Microsoft's. Fetching owners and appRoleAssignments for each was
        # 600-1200 calls for objects nobody can act on.
        if ($isFirstParty) {
            $skipped++
            $own = @(); $appRole = @()
            # Deliberately skipped is KNOWN-empty-by-policy, not unknown:
            # detailSkipped = true tells the engine these fields are not
            # evidence. The null treatment below is for FAILED calls only.
            $ownKnown = $true; $appRoleKnown = $true
        } else {
            # Result objects, not bare .Items - a failed owners call must
            # yield hasNoOwner = null, not a fabricated AGT-003 finding, and a
            # failed appRoleAssignments call must yield an unknown permission
            # count, not "no application permissions". Same fix as groups.
            $ownR     = Invoke-Graph -Uri "servicePrincipals/$($sp.id)/owners?`$select=id,displayName&`$top=999" -Dataset 'spOwners'
            $appRoleR = Invoke-Graph -Uri "servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999" -Dataset 'spAppRoles'
            $own          = $ownR.Items
            $appRole      = $appRoleR.Items
            $ownKnown     = -not $ownR.Failed
            $appRoleKnown = -not $appRoleR.Failed
        }

        $myGrants = if ($grantsBySp.ContainsKey($sp.id)) { $grantsBySp[$sp.id] } else { @() }
        # principalId is NULL on every admin-consent (AllPrincipals) grant, so
        # a tenant that omits null properties drops the key - Get-Prop or crash
        # (simulator P07/P09, the #25 lesson applied to grants).
        $delegated = @($myGrants | ForEach-Object {
            [ordered]@{
                consentType = (Get-Prop $_ 'consentType')      # AllPrincipals = admin consent for everyone
                principalId = (Get-Prop $_ 'principalId')
                resourceId  = (Get-Prop $_ 'resourceId')
                scopes      = @(("$(Get-Prop $_ 'scope')" -split ' ') | Where-Object { $_ })
            } })

        $looksLikeAgent = $false
        foreach ($h in $agentHints) { if ($spName -like "*$h*") { $looksLikeAgent = $true; break } }

        # verifiedPublisher is an OBJECT, and Graph omits it entirely when the
        # publisher is unverified - so this needs the guarded read twice over.
        $vp = Get-Prop $sp 'verifiedPublisher'

        [ordered]@{
            id = (Get-Prop $sp 'id'); appId = (Get-Prop $sp 'appId'); displayName = $spName
            servicePrincipalType = $spType
            accountEnabled  = (Get-Prop $sp 'accountEnabled')
            createdDateTime = (Get-Prop $sp 'createdDateTime')
            publisherName   = (Get-Prop $sp 'publisherName')
            isPublisherVerified = [bool]($vp -and (Get-Prop $vp 'verifiedPublisherId'))
            isMicrosoftFirstParty = $isFirstParty
            isThirdParty = $isThirdParty
            isManagedIdentity = ($spType -eq 'ManagedIdentity')
            looksLikeAgent = $looksLikeAgent
            detailSkipped = $isFirstParty
            tags = @(Get-Prop $sp 'tags' @())
            ownerDataKnown = $ownKnown
            ownerCount = $(if ($ownKnown) { @($own).Count } else { $null })
            hasNoOwner = $(if ($isFirstParty) { $false }
                           elseif ($ownKnown) { @($own).Count -eq 0 }
                           else { $null })
            applicationPermissions = @($appRole | ForEach-Object {
                [ordered]@{ resourceId=(Get-Prop $_ 'resourceId'); resourceDisplayName=(Get-Prop $_ 'resourceDisplayName'); appRoleId=(Get-Prop $_ 'appRoleId') } })
            applicationPermissionsKnown = $appRoleKnown
            applicationPermissionCount = $(if ($appRoleKnown) { @($appRole).Count } else { $null })
            delegatedGrants = $delegated
            hasAdminConsentForAll = (@($delegated | Where-Object { $_.consentType -eq 'AllPrincipals' }).Count -gt 0)
            userConsentCount = @($delegated | Where-Object { $_.consentType -eq 'Principal' }).Count
        }
    })

    Write-Item "$skipped Microsoft first-party principals skipped for per-object detail"
    return $out
}

# ====================================================== 7b. PERMISSION CATALOG

function Get-VdnPermissionCatalog {
    <#
        Permission GUIDs are meaningless to the engine on their own - a rule
        saying "app holds Mail.ReadWrite" cannot fire against
        '810c84a8-4a9e-49e6-bf7d-12d183f40d01'.

        One lookup per resource that actually appears in the data. Graph,
        Exchange and SharePoint cover almost everything.

        These are Microsoft's public identifiers and are NEVER hashed.
    #>
    param([object[]] $Applications, [object[]] $ServicePrincipals)

    Write-Phase '7b. Permission catalogue'

    $resourceIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in $Applications) {
        foreach ($rp in $a.requestedPermissions) { if ($rp.resourceAppId) { [void]$resourceIds.Add($rp.resourceAppId) } }
    }
    foreach ($sp in $ServicePrincipals) {
        foreach ($d in $sp.delegatedGrants) { if ($d.resourceId) { [void]$resourceIds.Add($d.resourceId) } }
    }

    return @(foreach ($rid in $resourceIds) {
        # resourceId on a grant is an object id; resourceAppId on an app is an
        # appId. Try both.
        $r = Invoke-Graph -Quiet -Dataset 'permissionCatalog' `
             -Uri "servicePrincipals?`$filter=appId eq '$rid'&`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        $sp = $r.Items | Select-Object -First 1
        if (-not $sp) {
            $r = Invoke-Graph -Quiet -Dataset 'permissionCatalog' `
                 -Uri "servicePrincipals/$rid`?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
            $sp = $r.Items | Select-Object -First 1
        }
        if (-not $sp) { continue }

        # appRoles and oauth2PermissionScopes are omitted entirely when empty.
        [ordered]@{
            objectId = (Get-Prop $sp 'id')
            appId = (Get-Prop $sp 'appId')
            displayName = (Get-Prop $sp 'displayName')
            appRoles = @(Get-Prop $sp 'appRoles' @() | ForEach-Object {
                [ordered]@{ id=(Get-Prop $_ 'id'); value=(Get-Prop $_ 'value'); displayName=(Get-Prop $_ 'displayName') } })
            delegatedScopes = @(Get-Prop $sp 'oauth2PermissionScopes' @() | ForEach-Object {
                [ordered]@{ id=(Get-Prop $_ 'id'); value=(Get-Prop $_ 'value'); type=(Get-Prop $_ 'type') } })
        }
    })
}

# ==================================================== 8. CONDITIONAL ACCESS

function Get-VdnConditionalAccess {
    Write-Phase '8. Conditional Access'

    # beta, not v1.0: only beta carries templateId, which is the one property
    # that tells a MICROSOFT-MANAGED policy from one the customer wrote. Seen
    # live 21 Sep: switching Security Defaults off made Microsoft create four
    # enabled policies on the spot - a tenant "with 5 CA policies" that had
    # written one. The engine must be able to tell the two apart.
    $pR = Invoke-Graph -Version beta -Uri 'identity/conditionalAccess/policies?$top=999' -Dataset 'caPolicies' -Quiet
    if ($pR.Failed) {
        Add-CollectionWarning -Dataset 'caPolicies' -Status $pR.Status -Code $pR.Code -Message (
            "CA policies unreadable (HTTP $($pR.Status)) - $(Get-VdnDenialReason -Code $pR.Code -Status $pR.Status -Permission 'Policy.Read.All')")
    } elseif (@($pR.Items).Count -eq 0) {
        # Kind 'info': we read it successfully and there genuinely are none.
        # That is a FINDING, not a gap, and the two must not look alike.
        Add-CollectionWarning -Dataset 'caPolicies' -Kind 'info' -Message 'no CA policies configured in this tenant'
    }

    $named = (Invoke-Graph -Uri 'identity/conditionalAccess/namedLocations?$top=999' -Dataset 'namedLocations').Items
    $stR = Invoke-Graph -Version beta -Uri 'identity/conditionalAccess/authenticationStrength/policies' -Dataset 'authStrengths' -Quiet
    if ($stR.Failed) {
        # Was -Quiet with no warning at all, so a failed call produced an empty
        # authenticationStrengths array indistinguishable from "none defined"
        # (simulator D12). Same class as every other "unknown is not zero" fix.
        Add-CollectionWarning -Dataset 'authStrengths' -Status $stR.Status -Code $stR.Code -Message (
            "authentication strength policies unreadable (HTTP $($stR.Status)) - beta endpoint; CA policies referencing a strength keep only the id")
    }
    $strengths = $stR.Items

    [ordered]@{
        policies = @($pR.Items | ForEach-Object {
            $cond  = Get-Prop $_ 'conditions'
            $u     = Get-Prop $cond 'users'
            $apps  = Get-Prop $cond 'applications'
            $grant = Get-Prop $_ 'grantControls'
            $state = Get-Prop $_ 'state'
            $as    = Get-Prop $grant 'authenticationStrength'
            $tpl = Get-Prop $_ 'templateId'
            [ordered]@{
                id = (Get-Prop $_ 'id'); displayName = (Get-Prop $_ 'displayName'); state = $state
                isReportOnly = ($state -eq 'enabledForReportingButNotEnforced')
                isEnabled = ($state -eq 'enabled')
                # templateId is set only on Microsoft-managed policies (portal: "Created by: MICROSOFT").
                # A template GUID is not a tenant identifier; the anonymiser leaves it alone.
                templateId = $tpl
                isMicrosoftManaged = [bool]$tpl
                createdDateTime = (Get-Prop $_ 'createdDateTime')
                modifiedDateTime = (Get-Prop $_ 'modifiedDateTime')
                # Flattened deliberately: the raw conditions object was a
                # PSCustomObject that the anonymiser walked straight past,
                # leaking real GUIDs into Free-mode output.
                includedUsers  = @(Get-Prop $u 'includeUsers'  @())
                excludedUsers  = @(Get-Prop $u 'excludeUsers'  @())
                includedGroups = @(Get-Prop $u 'includeGroups' @())
                excludedGroups = @(Get-Prop $u 'excludeGroups' @())
                includedRoles  = @(Get-Prop $u 'includeRoles'  @())
                excludedRoles  = @(Get-Prop $u 'excludeRoles'  @())
                includedApplications = @(Get-Prop $apps 'includeApplications' @())
                clientAppTypes = @(Get-Prop $cond 'clientAppTypes' @())
                builtInControls = @(Get-Prop $grant 'builtInControls' @())
                grantOperator = (Get-Prop $grant 'operator')
                authenticationStrengthId = (Get-Prop $as 'id')
            } })
        namedLocations = @($named | ForEach-Object {
            [ordered]@{ id=(Get-Prop $_ 'id'); displayName=(Get-Prop $_ 'displayName')
                        type=((Get-Prop $_ '@odata.type') -replace '#microsoft.graph.','')
                        isTrusted=(Get-Prop $_ 'isTrusted') } })
        authenticationStrengths = @($strengths | ForEach-Object {
            [ordered]@{ id=(Get-Prop $_ 'id'); displayName=(Get-Prop $_ 'displayName')
                        policyType=(Get-Prop $_ 'policyType')
                        allowedCombinations=@(Get-Prop $_ 'allowedCombinations' @()) } })
    }
}

# ============================================================== 9. POLICIES

function Get-VdnPolicies {
    Write-Phase '9. Tenant policies'
    $out = [ordered]@{}

    $ampR = Invoke-Graph -Version beta -Uri 'policies/authenticationMethodsPolicy' -Dataset 'policies' -Quiet
    if ($ampR.Failed) {
        Add-CollectionWarning -Dataset 'policies' -Status $ampR.Status -Code $ampR.Code -Message 'authenticationMethodsPolicy unreadable'
    } else {
        $amp = $ampR.Items | Select-Object -First 1
        $out.authenticationMethods = @(Get-Prop $amp 'authenticationMethodConfigurations' @() | ForEach-Object {
            $targets = @(Get-Prop $_ 'includeTargets' @())
            [ordered]@{
                # id here is a METHOD NAME (Fido2, Sms...), not an identifier.
                # It is in the sentinel list so the anonymiser leaves it alone.
                method = (Get-Prop $_ 'id')
                state  = (Get-Prop $_ 'state')
                targetTypes = @($targets | ForEach-Object { Get-Prop $_ 'targetType' })
                targetIds   = @($targets | ForEach-Object { Get-Prop $_ 'id' })
            } })

        # Doubles as the Guard 4 signal for the seeder: if Sms and Voice are
        # both disabled here, the lab cannot be seeded with any MFA at all.
        $telephonyStates = @($out.authenticationMethods | Where-Object { $_.method -in 'Sms','Voice' })
        $out.telephonyEnabled = @($telephonyStates | Where-Object { $_.state -eq 'enabled' }).Count -gt 0

        $campaign = Get-Prop (Get-Prop $amp 'registrationEnforcement') 'authenticationMethodsRegistrationCampaign'
        $out.registrationCampaign = [ordered]@{
            state = (Get-Prop $campaign 'state')
            snoozeDurationInDays = (Get-Prop $campaign 'snoozeDurationInDays')
        }
    }

    $authR = Invoke-Graph -Uri 'policies/authorizationPolicy' -Dataset 'policies' -Quiet
    if ($authR.Failed) {
        Add-CollectionWarning -Dataset 'policies' -Status $authR.Status -Code $authR.Code -Message 'authorizationPolicy unreadable'
        # The key used to be simply absent, which (a) is a StrictMode error for
        # the aggregator and (b) left aggregates.tenantDefaults as null where
        # the schema wants an object. Every field below is nullable in the
        # schema, so an all-null object with dataAvailable=false is both valid
        # and honest (simulator D12).
        $out.authorization = [ordered]@{
            dataAvailable = $false
            allowedToCreateApps = $null; allowedToCreateSecurityGroups = $null; allowedToReadOtherUsers = $null
            permissionGrantPoliciesAssigned = @(); allowInvitesFrom = $null; allowedToUseSspr = $null
            blockMsolPowerShell = $null; guestUserRoleId = $null
        }
    } else {
        $a = $authR.Items | Select-Object -First 1
        $p = Get-Prop $a 'defaultUserRolePermissions'
        $out.authorization = [ordered]@{
            dataAvailable = $true
            allowedToCreateApps = (Get-Prop $p 'allowedToCreateApps')
            allowedToCreateSecurityGroups = (Get-Prop $p 'allowedToCreateSecurityGroups')
            allowedToReadOtherUsers = (Get-Prop $p 'allowedToReadOtherUsers')
            permissionGrantPoliciesAssigned = @(Get-Prop $p 'permissionGrantPoliciesAssigned' @())
            allowInvitesFrom = (Get-Prop $a 'allowInvitesFrom')
            allowedToUseSspr = (Get-Prop $a 'allowedToUseSspr')
            blockMsolPowerShell = (Get-Prop $a 'blockMsolPowerShell')
            guestUserRoleId = (Get-Prop $a 'guestUserRoleId')
        }
    }

    $xtR = Invoke-Graph -Uri 'policies/crossTenantAccessPolicy/default' -Dataset 'policies' -Quiet
    if ($xtR.Failed) {
        Add-CollectionWarning -Dataset 'policies' -Status $xtR.Status -Code $xtR.Code -Message 'crossTenantAccessPolicy unreadable'
    } else {
        $x  = $xtR.Items | Select-Object -First 1
        $it = Get-Prop $x 'inboundTrust'
        $ac = Get-Prop $x 'automaticUserConsentSettings'
        $out.crossTenantDefault = [ordered]@{
            inboundTrustMfaAccepted      = (Get-Prop $it 'isMfaAccepted')
            inboundTrustCompliantDevice  = (Get-Prop $it 'isCompliantDeviceAccepted')
            automaticUserConsentInbound  = (Get-Prop $ac 'inboundAllowed')
            automaticUserConsentOutbound = (Get-Prop $ac 'outboundAllowed')
        }
    }

    return $out
}

# =============================================================== 10. DEVICES

function Get-VdnDevices {
    Write-Phase '10. Devices'

    $dR = Invoke-Graph -Dataset 'devices' -Uri ("devices?`$select=" + (@(
        'id','displayName','operatingSystem','operatingSystemVersion','trustType',
        'isCompliant','isManaged','accountEnabled','approximateLastSignInDateTime','registrationDateTime'
    ) -join ',') + "&`$top=999")

    $cR = Invoke-Graph -Uri 'deviceManagement/deviceCompliancePolicies?$top=999' -Dataset 'devices' -Quiet
    if ($cR.Failed) {
        # [VERIFY Saturday] Seen as 400, not 403, on the lab tenant. 400 is a
        # bad request, so "no licence" is a guess from the wrong status code -
        # the same mistake corrected on roleEligibility. Most likely Intune is
        # simply not provisioned in the tenant at all.
        Add-CollectionWarning -Dataset 'devices' -Status $cR.Status -Code $cR.Code -Message (
            "Intune compliance policies unreadable (HTTP $($cR.Status)$(if ($cR.Code) { ", code $($cR.Code)" })) - Intune not provisioned, no licence, or missing DeviceManagementConfiguration.Read.All")
    }

    [ordered]@{
        devices = @($dR.Items | ForEach-Object {
            [ordered]@{ id=(Get-Prop $_ 'id'); displayName=(Get-Prop $_ 'displayName')
                        operatingSystem=(Get-Prop $_ 'operatingSystem')
                        osVersion=(Get-Prop $_ 'operatingSystemVersion'); trustType=(Get-Prop $_ 'trustType')
                        isCompliant=(Get-Prop $_ 'isCompliant'); isManaged=(Get-Prop $_ 'isManaged')
                        accountEnabled=(Get-Prop $_ 'accountEnabled')
                        lastSignIn=(Get-Prop $_ 'approximateLastSignInDateTime')
                        registered=(Get-Prop $_ 'registrationDateTime') } })
        compliancePolicies = @($cR.Items | ForEach-Object {
            [ordered]@{ id=(Get-Prop $_ 'id'); displayName=(Get-Prop $_ 'displayName')
                        createdDateTime=(Get-Prop $_ 'createdDateTime')
                        type=(Get-Prop $_ '@odata.type') } })
    }
}

# =============================================================== 11. DELETED

function Get-VdnDeleted {
    Write-Phase '11. Recently deleted users'

    $r = Invoke-Graph -Dataset 'deletedUsers' `
         -Uri 'directory/deletedItems/microsoft.graph.user?$select=id,userPrincipalName,displayName,deletedDateTime,mail&$top=999'

    return @($r.Items | ForEach-Object {
        $deleted = Get-Prop $_ 'deletedDateTime'
        [ordered]@{
            id = (Get-Prop $_ 'id')
            userPrincipalName = (Get-Prop $_ 'userPrincipalName')
            displayName = (Get-Prop $_ 'displayName')
            mail = (Get-Prop $_ 'mail')
            deletedDateTime = $deleted
            daysUntilPurge = if ($deleted) {
                30 - [int]((Get-Date).ToUniversalTime() - [datetime]$deleted).TotalDays } else { $null }
        }
    })
}

# =============================================================== 12. LOGGING

function Get-VdnLogging {
    <#
        Also carries the meldplicht signals. Cbw / RDI focus area 2 is incident
        response within 24 and 72 hours, and you cannot report inside 24 hours
        on evidence you did not retain or an event nobody was told about. So
        the two questions are: how far back do the logs go, and does anything
        raise a hand.

        Everything here is a RAW signal. Whether 7 days is a finding is a rule
        decision, not a collector decision.
    #>
    param([object[]] $Licences)

    Write-Phase '12. Audit, logging and meldplicht posture'
    $out = [ordered]@{}

    # -NoPage on all three. These are readability PROBES, not collections. We
    # deliberately do not pull sign-in or audit rows in bulk - the volume is
    # enormous and the value is in retention, not in the rows.
    $s = Invoke-Graph -Uri 'auditLogs/signIns?$top=1' -Dataset 'logging' -Quiet -NoPage
    $out.signInLogsReadable = (-not $s.Failed)
    if ($s.Failed) {
        Add-CollectionWarning -Dataset 'logging' -Status $s.Status -Code $s.Code -Message (
            "sign-in logs unreadable (HTTP $($s.Status)) - $(Get-VdnDenialReason -Code $s.Code -Status $s.Status -Permission 'AuditLog.Read.All')")
    }

    $d = Invoke-Graph -Uri 'auditLogs/directoryAudits?$top=1' -Dataset 'logging' -Quiet -NoPage
    $out.directoryAuditReadable = (-not $d.Failed)
    if ($d.Failed) {
        # The sign-in probe warned on failure, this one silently wrote false.
        # A 503 and a 403 then looked identical to the engine (simulator D12).
        Add-CollectionWarning -Dataset 'logging' -Status $d.Status -Code $d.Code -Message (
            "directory audit log unreadable (HTTP $($d.Status)) - $(Get-VdnDenialReason -Code $d.Code -Status $d.Status -Permission 'AuditLog.Read.All' -Licence '')")
    }

    # ALERTING IS NOT COLLECTED. Deliberately, after removing a call that
    # should never have been here.
    #
    # v0.6.0 through v0.8.0 probed 'beta/auditLogs/monitoring/alertRules'. That
    # endpoint returned HTTP 400 on every run, and it is not in the Graph
    # v1.0 or beta reference - it appears to have been invented when this
    # function was written. The consequence was not cosmetic: monitoringConfigured
    # would have been null on every tenant forever, so half of the meldplicht
    # rule would permanently report "not assessed" while looking like a
    # capability we had.
    #
    # Treated the same way as the Azure-side diagnostic export: stated as
    # unreadable rather than guessed at. If the real Entra health-monitoring
    # surface is identified from the documentation, wire it up then - do not
    # guess a second path.
    # Local, not $out - it belongs in the meldplicht block only, which is where
    # LOG-001 reads it. v0.8.1 set it in both places and the 08:40 file carried
    # the pair twice.
    $alertingNote = 'Not collected. Entra alerting state is not readable through the Graph endpoints this collector uses. Confirm by hand, or via the Azure module once written.'

    # Retention inside Entra is a function of licence, not a setting anyone can
    # read: Free keeps 7 days, P1/P2 keep 30. Beyond that you must export.
    $plans = @($Licences | ForEach-Object { $_.servicePlans } | Where-Object { $_ })
    $hasPremium = @($plans | Where-Object { $_ -like 'AAD_PREMIUM*' }).Count -gt 0
    # If subscribedSkus failed, retention and premium are UNKNOWN - not
    # "7 days, no premium". An unread licence list is not an empty one.
    $licKnown = Test-DatasetOk 'licences'

    # RAW SIGNALS ONLY. No verdicts.
    #
    # v0.8.0 emitted coversReportingWindow and coversTypicalDwellTime. Both
    # were removed: they are judgements, not facts about the tenant, and they
    # contradicted this collector's own stated principle that thresholds live
    # in rules.yaml. inactiveByLastSignIn is deliberately raw with ageDays
    # beside it for exactly this reason; retention gets the same treatment.
    #
    # "Typical dwell time" is a claim about the threat landscape, not about
    # the customer. Baking 30-days-is-enough into the data means arguing with
    # a client about a number we put there ourselves. LOG-001 decides.
    $out.meldplicht = [ordered]@{
        licenceDataAvailable    = $licKnown
        retentionDaysInEntra    = $(if (-not $licKnown) { $null } elseif ($hasPremium) { 30 } else { 7 })
        # NOT read from a setting. null when the licence was not read (0.3
        # amendment, D-028): the origin of a number that does not exist is
        # not 'licence'. Found by validate 0.3 on simulator T07 (#46).
        retentionInferredFrom   = $(if ($licKnown) { 'licence' } else { $null })
        premiumLicencePresent   = $(if ($licKnown) { $hasPremium } else { $null })
        alertingConfigured      = $null
        alertingNote            = $alertingNote

        # Graph cannot see Azure Monitor diagnostic settings - they are a
        # resource-level setting on the tenant's Azure side. null means UNKNOWN,
        # and a rule must not treat unknown as absent: a client exporting to
        # Sentinel would otherwise be told they retain nothing.
        diagnosticExportConfigured = $null
        diagnosticExportNote       = 'Not visible to Graph. Requires the Azure module or manual confirmation.'

        # Context for whoever writes the rule, NOT a computed verdict:
        # the Cbw windows are 24h (early warning) and 72h (full report). Both
        # fit inside even 7-day retention, so the finding is never "you cannot
        # meet the deadline" - a client will correctly point out that 72 hours
        # is less than 7 days. The finding is that a short window closes over
        # the evidence of HOW an incident started, because discovery normally
        # takes longer than the window.
        reportingWindowHours    = @(24, 72)
    }

    $out.note = 'Diagnostic settings export to Log Analytics or storage is an Azure resource setting, collected by the Azure module, not by Graph.'
    return $out
}

# ============================================================= 13. WORKLOADS

function Get-VdnWorkloads {
    Write-Phase '13. Workload configuration (ScubaGear)'

    # Not-collected is an OBJECT that says why, never $null: the schema types
    # datasets.workloads as object, and a Full-mode file with "workloads": null
    # was INVALID on every simulated tenant (18 Sep) - Full mode had never run.
    if (-not $IncludeScubaGear) { Write-Item 'skipped'; return [ordered]@{ collected = $false; reason = 'not requested (-IncludeScubaGear absent)' } }
    if ($Mode -eq 'Free') {
        Write-Item 'skipped in Free mode - ScubaGear output carries tenant names and domains'
        return [ordered]@{ collected = $false; reason = 'Free mode' }
    }
    if (-not (Get-Module ScubaGear -ListAvailable)) {
        Add-CollectionWarning -Dataset 'workloads' -Message 'ScubaGear not installed'
        return [ordered]@{ collected = $false; reason = 'ScubaGear not installed' }
    }

    try {
        Import-Module ScubaGear
        $scubaOut = Join-Path $OutputPath 'scubagear'
        New-Item -ItemType Directory -Path $scubaOut -Force | Out-Null
        Invoke-SCuBA -ProductNames aad, exo, sharepoint, teams, defender -OutPath $scubaOut -Quiet | Out-Null

        $json = Get-ChildItem $scubaOut -Recurse -Filter 'ScubaResults*.json' |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $json) { Add-CollectionWarning -Dataset 'workloads' -Message 'no results file produced'; return [ordered]@{ collected = $false; reason = 'ScubaGear produced no results file' } }

        $results = Get-Content $json.FullName -Raw | ConvertFrom-Json
        return [ordered]@{ source='ScubaGear'; resultsFile=$json.Name; summary=$results.Summary; results=$results.Results }
    } catch {
        Add-CollectionWarning -Dataset 'workloads' -Message "ScubaGear failed: $($_.Exception.Message)"
        return [ordered]@{ collected = $false; reason = 'ScubaGear failed - see warnings' }
    }
}

# ============================================================ anonymisation

# Fields whose VALUE is an identifier. Note 'id' is NOT here globally - it
# means different things in different datasets, and hashing it in
# policies.authenticationMethods destroyed the method name. Since v0.8.12 an
# 'id' IS hashed when its value is a GUID (see Protect-Field, defect #36):
# object ids must hash exactly like the memberIds / ownerIds / principalId
# that point at them, or every join in the engine silently returns nothing.
$script:IdFields = @(
    'principalId','resourceId','clientId','appId','objectId','tenantId',
    'userPrincipalName','principalUpn','mail','displayName','userDisplayName',
    'principalName','givenName','surname','employeeId','publisherName','companyName',
    'department','jobTitle',        # #38: quasi-identifying free text, 22 Sep
    'memberIds','nestedGroupIds','ownerIds','targetIds',
    'includedUsers','excludedUsers','includedGroups','excludedGroups',
    'includedRoles','excludedRoles','includedApplications'
)

# Free text that cannot be safely hashed because the content itself identifies.
# Dropped rather than hashed.
$script:DropFields = @(
    'description','membershipRule','notes','redirectUris','homepage',
    'technicalNotificationMails','name'
)

$script:GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Subtrees whose 'id' values are Microsoft catalogue constants, not tenant
# objects: permissionCatalog[].appRoles[].id / oauth2PermissionScopes[].id are
# what servicePrincipals[].applicationPermissions[].appRoleId (NOT hashed)
# joins to. Hashing them would break that join the same way #36 broke the
# group one.
$script:AnonKeepIdsUnder = @('permissionCatalog')

function ConvertTo-AnonymisedCollection {
    param([hashtable] $Data)

    $script:AnonHashIds = $true

    function Protect-Field {
        param($Key, $Value)
        if ($script:DropFields -contains $Key) {
            # Keep the TYPE: an array field becomes [], a scalar '(removed)'.
            # '(removed)' in place of redirectUris / technicalNotificationMails
            # failed the schema on every anonymised file (simulator, 18 Sep).
            if ($Value -is [array]) { return ,@() }
            return '(removed)'
        }
        if ($script:IdFields -contains $Key) {
            if ($Value -is [array]) {
                # Leading comma: without it an empty list unrolls to $null and a
                # one-element list to a scalar. First -Anonymise run ever (the
                # simulator, 18 Sep) produced ~70 schema violations from this.
                return ,@($Value | ForEach-Object {
                    if ($_ -in $script:Sentinels) { $_ } else { Protect-Id ([string]$_) } })
            }
            if ($Value -in $script:Sentinels) { return $Value }
            return (Protect-Id ([string]$Value))
        }
        # Defect #36: an object id is an identifier too. Only when it looks like
        # one - method names ('Fido2') and sentinels pass through untouched.
        if ($Key -eq 'id' -and $script:AnonHashIds -and $Value -is [string] -and
            $Value -match $script:GuidPattern -and $Value -notin $script:Sentinels) {
            return (Protect-Id $Value)
        }
        # Two unroll points, two commas: Walk wraps its array result, and this
        # return must wrap it AGAIN or the pipeline flattens it on the way out.
        $walked = Walk $Value
        return ,$walked
    }

    function Walk {
        param($Node)
        if ($null -eq $Node) { return $null }
        if ($Node -is [System.Collections.IDictionary]) {
            $new = [ordered]@{}
            foreach ($k in $Node.Keys) {
                if ($k -in $script:AnonKeepIdsUnder) {
                    $prev = $script:AnonHashIds
                    $script:AnonHashIds = $false
                    try     { $new[$k] = Protect-Field -Key $k -Value $Node[$k] }
                    finally { $script:AnonHashIds = $prev }
                } else {
                    $new[$k] = Protect-Field -Key $k -Value $Node[$k]
                }
            }
            return $new
        }
        # THIS was missing in v0.4.0. Graph returns PSCustomObject, so every
        # raw object passed through with real identifiers intact.
        if ($Node -is [System.Management.Automation.PSCustomObject]) {
            $new = [ordered]@{}
            foreach ($p in $Node.PSObject.Properties) { $new[$p.Name] = Protect-Field -Key $p.Name -Value $p.Value }
            return $new
        }
        if ($Node -is [array]) { return ,@($Node | ForEach-Object { Walk $_ }) }   # comma: keep [] and [x] as arrays (defect #24)
        return $Node
    }

    return (Walk $Data)
}

# ======================================================= free-mode aggregates

function ConvertTo-FreeAggregate {
    <#
        Free mode emits THIS, and only this. Counts and distributions. No user
        object, no group object, no service principal object, no identifier of
        any kind - hashed or otherwise.

        The reason is not squeamishness: hashed per-person records are still
        personal data under GDPR, so shipping them would make the website's
        promise false.
    #>
    param([hashtable] $D)

    $u   = @($D.users)
    $am  = @($D.authMethods)
    $g   = @($D.groups)
    $r   = @($D.roles)
    $app = @($D.applications)
    $sp  = @($D.servicePrincipals)
    $ca  = @($D.conditionalAccess.policies)

    $enabled = @($u | Where-Object accountEnabled)
    $admins  = @($am | Where-Object isAdmin)

    # Summed by hand, not with Measure-Object -Property.
    #
    # An Entra ID Free tenant has no subscribedSkus at all, so this list is
    # empty, and Measure-Object -Property against an empty collection throws
    # "the value of argument 'unassigned' is not valid" - which reads like a
    # data problem and is actually an empty-input problem. Crashed the second
    # smoke test here, after all thirteen phases had passed.
    $unassignedTotal = 0; $overAssignedTotal = 0
    foreach ($lic in @($D.tenant.licences)) {
        $unassignedTotal   += [int](Get-Prop $lic 'unassigned' 0)
        $overAssignedTotal += [int](Get-Prop $lic 'overAssigned' 0)
    }

    # ---------------------------------------------------------------------
    # AVAILABILITY. Every section below asks "did the call behind this
    # succeed?" before emitting a number. A failed call yields null.
    #
    # Two distinct questions, and conflating them produced the 17 Sep file:
    #   ok       - the call succeeded at all
    #   usable   - it succeeded AND returned enough rows to be trusted
    # ---------------------------------------------------------------------
    $usersOk   = Test-DatasetOk 'users'
    $amOk      = Test-DatasetOk 'authMethods'
    $groupsOk  = Test-DatasetOk 'groups'
    $rolesOk   = Test-DatasetOk 'roleAssignments'
    $roleDefOk = Test-DatasetOk 'roleDefinitions'
    $eligOk    = Test-DatasetOk 'roleEligibility'
    $appsOk    = Test-DatasetOk 'applications'
    $spOk      = Test-DatasetOk 'servicePrincipals'
    $caOk      = Test-DatasetOk 'caPolicies'
    $devOk     = Test-DatasetOk 'devices'
    $delOk     = Test-DatasetOk 'deletedUsers'
    # Delegated grants are one global call. If it failed, every SP row shows
    # zero grants - and the consent aggregates would read "nobody consented"
    # off an unread dataset. Unknown, not zero.
    $grantsOk  = Test-DatasetOk 'oauth2Grants'
    # subscribedSkus is one call. If it failed, the tenant has not "no licences"
    # - it has UNKNOWN licences. Before this gate a failed call produced
    # licenceSkus [], unassignedLicences 0, premiumLicencePresent false and
    # retentionDaysInEntra 7: LIC-001 would fail ("no P1") and LOG-001 would
    # read seven days, both off an unread dataset. Simulator T07, 18 Sep.
    $licOk     = Test-DatasetOk 'licences'

    $signInsKnown = [bool]$script:SignInActivityAvailable

    # PARTIAL data is the case the null-guard missed. On 17 Sep the report
    # returned 1 row for a 3-user tenant: registrationReportAvailable was
    # true, the guard did not fire, and the file said "0 users without MFA"
    # about a tenant where two of three had no method at all.
    #
    # An absent dataset and a one-third-populated dataset are equally
    # unusable. The report lags for hours after a tenant is licensed or a user
    # is created, so this is the normal state of a freshly onboarded client -
    # exactly who runs the free scan.
    $reportRows     = $am.Count
    $reportCoverage = $script:ReportCoverage
    # Coverage must be KNOWN and sufficient. The previous expression accepted
    # $null coverage - which happens when the users call fails - so unknown
    # coverage passed as full coverage, in the guard that exists because
    # partial data produced "0 users without MFA" on 17 Sep. Unknown is not
    # full any more than unknown is zero.
    $amUsable       = ($amOk -and $reportRows -gt 0 -and
                       $null -ne $reportCoverage -and $reportCoverage -ge $MinReportCoverage)

    # Registered at least one method, every method they hold is telephony, AND
    # the report counts that as MFA (D-024, v0.8.20). Deliberately NOT "has a
    # phone method" - a user with a phone AND an authenticator is fine on
    # 1 Feb 2027; a user with only a phone is not. And when the tenant policy
    # has SMS and voice disabled, the report says isMfaRegistered false for a
    # phone-only user: that user is not "telephony-only MFA", they have no
    # second factor at all - registeredButNotMfaCapable, below.
    $telephonyOnly = @($am | Where-Object {
        $methods = @($_.methodsRegistered | Where-Object { $_ })
        $_.isMfaRegistered -and
        $methods.Count -gt 0 -and
        @($methods | Where-Object { $_ -notin $script:TelephonyMethods }).Count -eq 0
    })
    # Registered something, and the report still says not MFA-registered.
    # Found in the lab 22 Sep: 10 users with mobilePhone, isMfaRegistered
    # false, because Sms and Voice were disabled in the authentication methods
    # policy. The report decides what counts; we pass its verdict on.
    $registeredButNotMfaCapable = @($am | Where-Object {
        @($_.methodsRegistered | Where-Object { $_ }).Count -gt 0 -and -not $_.isMfaRegistered
    })
    # D-025: a guest's MFA and licence are the home tenant's business. The
    # report's userType is normalised in Get-VdnAuthMethods, so 'Guest' here.
    $amMembers = @($am | Where-Object { $_.userType -ne 'Guest' })

    [ordered]@{
        tenant = [ordered]@{
            # Deliberately NOT tenantId, NOT domain names, NOT notification
            # addresses. The client knows which tenant they ran it on.
            userCount               = $(if ($usersOk) { $u.Count } else { $null })
            securityDefaultsEnabled = $D.tenant.securityDefaultsEnabled
            licenceDataAvailable    = $licOk
            # Leading comma: a one-SKU tenant must serialise as ["SPB"], not "SPB".
            # $( ) unrolls a single-element array; the comma wraps it so it
            # survives. Caught by the simulator (T01/T05/T06/T08/T09), 18 Sep.
            licenceSkus             = $(if ($licOk) { ,@($D.tenant.licences | ForEach-Object { Get-Prop $_ 'skuPartNumber' }) } else { $null })
            unassignedLicences      = $(if ($licOk) { $unassignedTotal } else { $null })
            # Seats consumed beyond what is purchased (simulator D14: 1200 on 10).
            overAssignedLicences    = $(if ($licOk) { $overAssignedTotal } else { $null })
        }
        identity = [ordered]@{
            usersDataAvailable  = $usersOk
            usersTotal          = $(if ($usersOk) { $u.Count } else { $null })
            usersEnabled        = $(if ($usersOk) { $enabled.Count } else { $null })
            usersDisabled       = $(if ($usersOk) { $u.Count - $enabled.Count } else { $null })
            guests              = $(if ($usersOk) { @($u | Where-Object { $_.userType -eq 'Guest' }).Count } else { $null })
            # D-025 (v0.8.20): members only - a guest carries no licence here by design.
            unlicensedEnabled   = $(if ($usersOk) { @($enabled | Where-Object { -not $_.isLicensed -and $_.userType -ne 'Guest' }).Count } else { $null })
            # null, not a count, when signInActivity was unreadable. Otherwise
            # every user in the tenant looks never-signed-in - which the 09:59
            # smoke test proved false by reporting 3 of 3 while the person
            # running it had signed in ninety seconds earlier.
            signInDataAvailable = $signInsKnown
            neverSignedIn       = $(if ($usersOk -and $signInsKnown) { @($u | Where-Object neverSignedIn).Count } else { $null })
            # D-004: the AGGREGATE applies the age exemption - an account
            # younger than the threshold cannot be N-days-inactive (the seeded
            # lab reported 18 "inactive" accounts created the day before). The
            # per-user record stays RAW; the threshold is declared beside the
            # count so the engine can cross-check it against rules.yaml.
            # Exempt only when ageDays < threshold: exactly threshold days old is
            # NOT exempt (-ge, v0.8.20); unknown age is not exempt (D-027).
            # ENABLED accounts only, like the IDN-014 record scope: a disabled
            # account is not "inactive", it is switched off. Found by validate
            # 0.3 on simulator D20 (#45) - the generator shared the assumption.
            inactiveByLastSignIn= $(if ($usersOk -and $signInsKnown) { @($enabled | Where-Object { $_.inactiveByLastSignIn -and ($null -eq $_.ageDays -or $_.ageDays -ge $InactiveDays) }).Count } else { $null })
            inactiveThresholdDays = $InactiveDays
            syncedFromOnPrem    = $(if ($usersOk) { @($u | Where-Object syncedFromOnPrem).Count } else { $null })
            passwordNeverExpires= $(if ($usersOk) { @($u | Where-Object { $_.passwordPolicies -like '*DisablePasswordExpiration*' }).Count } else { $null })
        }
        # EVERY COUNT HERE IS null WHEN THE REGISTRATION REPORT IS UNAVAILABLE.
        #
        # The 09:59 smoke test emitted registrationReportAvailable=false next to
        # adminsWithoutMfa=0 on a tenant with three Global Administrators and no
        # MFA data at all. A dossier built from that would have stated the exact
        # opposite of the truth, in the single most important finding we sell.
        #
        # Zero means "none". Unknown means null. They are not the same number
        # and a scanner that confuses them is worse than no scanner.
        authentication = [ordered]@{
            registrationReportAvailable = $amOk
            registrationReportRows      = $(if ($amOk) { $reportRows } else { $null })   # #41: unread is null, not 0
            registrationReportCoverage  = $reportCoverage
            registrationReportUsable    = $amUsable
            mfaRegistered       = $(if ($amUsable) { @($am | Where-Object isMfaRegistered).Count } else { $null })
            # D-025 (v0.8.20): members only. mfaRegistered stays the whole report.
            mfaNotRegistered    = $(if ($amUsable) { @($amMembers | Where-Object { -not $_.isMfaRegistered }).Count } else { $null })
            passwordlessCapable = $(if ($amUsable) { @($am | Where-Object isPasswordlessCapable).Count } else { $null })
            adminsTotal         = $(if ($amUsable) { $admins.Count } else { $null })
            adminsWithoutMfa    = $(if ($amUsable) { @($admins | Where-Object { -not $_.isMfaRegistered }).Count } else { $null })

            # Registered SOMETHING, but everything they registered is telephony.
            # On 1 Feb 2027 Microsoft stops delivering SMS and voice, so these
            # users lose their only second factor on a known date.
            telephonyOnly       = $(if ($amUsable) { $telephonyOnly.Count } else { $null })
            adminsTelephonyOnly = $(if ($amUsable) { @($telephonyOnly | Where-Object isAdmin).Count } else { $null })
            # v0.8.20 (D-024): has methods, and the report says NOT MFA-registered -
            # the phone the tenant policy forbids. No second factor today.
            registeredButNotMfaCapable = $(if ($amUsable) { $registeredButNotMfaCapable.Count } else { $null })
            telephonyRetirement = $script:TelephonyRetirement

            # methodsInUse stays a list even when partial - it is a
            # distribution of what WAS seen, not a claim about the population.
            # It was the one field left as [] while its siblings were null,
            # which was inconsistent; now it is explicitly labelled partial.
            methodsInUsePartial = (-not $amUsable)
            methodsInUse        = @($am | ForEach-Object { $_.methodsRegistered } | Where-Object { $_ } |
                                    Group-Object | ForEach-Object { [ordered]@{ method=$_.Name; users=$_.Count } })
        }
        groups = [ordered]@{
            dataAvailable = $groupsOk
            # false when any group's members or owners call failed. The counts
            # below then cover only the rows that answered - a lower bound,
            # not the population - and a rule should treat them accordingly.
            membershipDataComplete = $(if ($groupsOk) {
                @($g | Where-Object { $_.memberDataKnown -eq $false -or $_.ownerDataKnown -eq $false }).Count -eq 0 } else { $null })
            total       = $(if ($groupsOk) { $g.Count } else { $null })
            empty       = $(if ($groupsOk) { @($g | Where-Object isEmpty).Count } else { $null })
            withoutOwner= $(if ($groupsOk) { @($g | Where-Object hasNoOwner).Count } else { $null })
            nested      = $(if ($groupsOk) { @($g | Where-Object { $_.memberGroupCount -gt 0 }).Count } else { $null })
            dynamic     = $(if ($groupsOk) { @($g | Where-Object isDynamic).Count } else { $null })
            roleAssignable = $(if ($groupsOk) { @($g | Where-Object isAssignableToRole).Count } else { $null })
        }
        privilegedAccess = [ordered]@{
            assignmentDataAvailable = $rolesOk
            roleNamesAvailable      = $roleDefOk
            # PIM eligibility needs P2. On a P1 tenant the call 400s, and
            # emitting 0 there claims "nobody holds eligible assignments" when
            # the truth is that eligibility cannot be read at all.
            eligibilityDataAvailable = $eligOk
            permanentAssignments = $(if ($rolesOk) { @($r | Where-Object { $_.assignmentType -eq 'permanent' }).Count } else { $null })
            eligibleAssignments  = $(if ($eligOk)  { @($r | Where-Object { $_.assignmentType -eq 'eligible' }).Count } else { $null })
            # Depends on roleName, so it needs the DEFINITIONS call as well as
            # the assignments call - that is the pair that produced a silent 0
            # on 15 Sep.
            globalAdministrators = $(if ($rolesOk -and $roleDefOk) { @($r | Where-Object { $_.roleName -eq 'Global Administrator' }).Count } else { $null })
            groupBasedAssignments= $(if ($rolesOk) { @($r | Where-Object isGroupAssignment).Count } else { $null })
            # Group-Object with a SCRIPT BLOCK, not a bare property name.
            # -Property does not resolve keys on an [ordered] dictionary, so
            # `Group-Object roleName` put all three assignments under the name
            # "" in the 09:59 run - while globalAdministrators, which uses a
            # script block, correctly said 3. Two fields, same data, disagreeing.
            rolesInUse           = @($r | Group-Object { $_.roleName } | ForEach-Object {
                                       [ordered]@{ role=$_.Name; assignments=$_.Count } })
        }
        applicationsAndAgents = [ordered]@{
            appDataAvailable     = $appsOk
            spDataAvailable      = $spOk
            # false when any per-object owners or appRoleAssignments call
            # failed; the owner/permission counts below then cover only the
            # rows that answered. First-party SPs skipped by policy do NOT
            # count as incomplete - detailSkipped marks those.
            ownerDataComplete    = $(if ($appsOk -and $spOk) {
                (@($app | Where-Object { $_.ownerDataKnown -eq $false }).Count +
                 @($sp  | Where-Object { $_.ownerDataKnown -eq $false -or $_.applicationPermissionsKnown -eq $false }).Count) -eq 0 } else { $null })
            registrations        = $(if ($appsOk) { $app.Count } else { $null })
            withoutOwner         = $(if ($appsOk) { @($app | Where-Object hasNoOwner).Count } else { $null })
            withExpiredCredential= $(if ($appsOk) { @($app | Where-Object hasExpiredCredential).Count } else { $null })
            multiTenant          = $(if ($appsOk) { @($app | Where-Object isMultiTenant).Count } else { $null })
            servicePrincipalsTotal   = $(if ($spOk) { $sp.Count } else { $null })
            servicePrincipalsThirdParty = $(if ($spOk) { @($sp | Where-Object isThirdParty).Count } else { $null })
            thirdPartyWithoutOwner   = $(if ($spOk) { @($sp | Where-Object { $_.isThirdParty -and $_.hasNoOwner }).Count } else { $null })
            # Gated on the GRANTS call as well as the SP call: consent lives in
            # oauth2PermissionGrants, and if that one global call failed every
            # SP looks unconsented - "nobody consented" off an unread dataset.
            withAdminConsentForAll   = $(if ($spOk -and $grantsOk) { @($sp | Where-Object hasAdminConsentForAll).Count } else { $null })
            withUserConsentOnly      = $(if ($spOk -and $grantsOk) { @($sp | Where-Object { $_.userConsentCount -gt 0 -and -not $_.hasAdminConsentForAll }).Count } else { $null })
            looksLikeAgent           = $(if ($spOk) { @($sp | Where-Object looksLikeAgent).Count } else { $null })
        }
        conditionalAccess = [ordered]@{
            # On a tenant without P1 this call fails, and 0 would read as "no
            # Conditional Access policies exist" - which is a finding - rather
            # than "CA is not readable here", which is a gap.
            dataAvailable = $caOk
            total      = $(if ($caOk) { $ca.Count } else { $null })
            enabled    = $(if ($caOk) { @($ca | Where-Object isEnabled).Count } else { $null })
            reportOnly = $(if ($caOk) { @($ca | Where-Object isReportOnly).Count } else { $null })
            disabled   = $(if ($caOk) { @($ca | Where-Object { -not $_.isEnabled -and -not $_.isReportOnly }).Count } else { $null })
            # ENABLED only (D-009, defect #40): a report-only policy enforces
            # nothing. Found by the engine's validate.py against the real lab
            # Full scan - requiresMfa said 4 with 3 enforced.
            appliesToAllUsers = $(if ($caOk) { @($ca | Where-Object { $_.isEnabled -and $_.includedUsers -contains 'All' }).Count } else { $null })
            requiresMfa= $(if ($caOk) { @($ca | Where-Object { $_.isEnabled -and $_.builtInControls -contains 'mfa' }).Count } else { $null })
            # v0.8.20 (D-023): the same enabled+mfa count split by origin; they sum to requiresMfa.
            requiresMfaMicrosoftManaged = $(if ($caOk) { @($ca | Where-Object { $_.isEnabled -and $_.builtInControls -contains 'mfa' -and $_.isMicrosoftManaged }).Count } else { $null })
            requiresMfaCustomerCreated  = $(if ($caOk) { @($ca | Where-Object { $_.isEnabled -and $_.builtInControls -contains 'mfa' -and -not $_.isMicrosoftManaged }).Count } else { $null })
            # Microsoft-managed (templateId set) vs written by the tenant. Both count in the
            # figures above; a rule that asks "did the customer configure CA?" needs the split.
            microsoftManaged = $(if ($caOk) { @($ca | Where-Object isMicrosoftManaged).Count } else { $null })
            customerCreated  = $(if ($caOk) { @($ca | Where-Object { -not $_.isMicrosoftManaged }).Count } else { $null })
        }
        # Absent, not null, when authorizationPolicy was unreadable (D12: every
        # call 403) - and a missing hashtable key is a StrictMode error.
        tenantDefaults = $(if ($D.policies -and $D.policies.Contains('authorization')) { $D.policies.authorization } else { $null })    # booleans only, no identifiers
        devices = [ordered]@{
            dataAvailable = $devOk
            total     = $(if ($devOk) { @($D.devices.devices).Count } else { $null })
            managed   = $(if ($devOk) { @($D.devices.devices | Where-Object isManaged).Count } else { $null })
            compliant = $(if ($devOk) { @($D.devices.devices | Where-Object isCompliant).Count } else { $null })
            # Reported 0 on 15 Sep off a call that had returned HTTP 400 -
            # "no compliance policies" when Intune was simply not readable.
            compliancePolicies = $(if ($devOk) { @($D.devices.compliancePolicies).Count } else { $null })
        }
        deletedUsers = [ordered]@{
            dataAvailable    = $delOk
            inRecoveryWindow = $(if ($delOk) { @($D.deletedUsers).Count } else { $null })
        }
        logging      = $D.logging
    }
}

# ==================================================================== main

Write-Host ''
Write-Host '=======================================================' -ForegroundColor Cyan
Write-Host " Veridan collector $COLLECTOR_VERSION - mode: $Mode" -ForegroundColor Cyan
Write-Host '=======================================================' -ForegroundColor Cyan

$scopes = @('Directory.Read.All','Policy.Read.All','AuditLog.Read.All','Application.Read.All',
            'Reports.Read.All','RoleManagement.Read.Directory',
            'DeviceManagementConfiguration.Read.All','Organization.Read.All')

try {
    if ($Mode -eq 'Full') {
        if (-not ($TenantId -and $ClientId -and $CertificateThumbprint)) {
            throw 'Full mode requires -TenantId, -ClientId and -CertificateThumbprint.'
        }
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -ContextScope Process -NoWelcome
    } else {
        if ($TenantId) {
            Connect-MgGraph -TenantId $TenantId -Scopes $scopes -ContextScope Process -NoWelcome
        } else {
            Write-Host '   ! No -TenantId given; connecting to your default tenant.' -ForegroundColor Yellow
            Connect-MgGraph -Scopes $scopes -ContextScope Process -NoWelcome
        }
    }

    $ctx = Get-MgContext
    Write-Item "connected to $($ctx.TenantId) as $(if ($ctx.Account) { $ctx.Account } else { $ctx.ClientId })"
    # O-9 (v0.8.22): before the first data call. The finally below disconnects.
    Assert-VdnTenantAllowed -Connected $ctx.TenantId -Requested $TenantId -Forbidden (Get-VdnForbiddenTenantIds)

    $started = (Get-Date).ToUniversalTime()

    $datasets = [ordered]@{}
    $datasets.tenant            = Measure-Phase 'tenant'            { Get-VdnTenant }
    $tenantOrgId                = $datasets.tenant.tenantId          # no second organization call
    $datasets.users             = @(Measure-Phase 'users'            { Get-VdnUsers })
    $datasets.authMethods       = @(Measure-Phase 'authMethods'      { Get-VdnAuthMethods })
    $datasets.groups            = @(Measure-Phase 'groups'           { Get-VdnGroups })
    $datasets.roles             = @(Measure-Phase 'roles'            { Get-VdnRoles })
    $datasets.applications      = @(Measure-Phase 'applications'     { Get-VdnApplications })
    $datasets.servicePrincipals = @(Measure-Phase 'servicePrincipals'{ Get-VdnServicePrincipals -TenantOrgId $tenantOrgId })
    $datasets.permissionCatalog = @(Measure-Phase 'permissionCatalog'{
                                      Get-VdnPermissionCatalog -Applications $datasets.applications `
                                                               -ServicePrincipals $datasets.servicePrincipals })
    $datasets.conditionalAccess = Measure-Phase 'conditionalAccess'  { Get-VdnConditionalAccess }
    $datasets.policies          = Measure-Phase 'policies'           { Get-VdnPolicies }
    $datasets.devices           = Measure-Phase 'devices'            { Get-VdnDevices }
    $datasets.deletedUsers      = @(Measure-Phase 'deletedUsers'     { Get-VdnDeleted })
    $datasets.logging           = Measure-Phase 'logging'            { Get-VdnLogging -Licences $datasets.tenant.licences }
    $datasets.workloads         = Measure-Phase 'workloads'          { Get-VdnWorkloads }

    $finished = (Get-Date).ToUniversalTime()

    # ---------------------------------------------------- report coverage
    # Computed here, not in the aggregator, because the warning has to exist
    # before the payload is built - the warnings array is serialised first.
    $userRows   = @($datasets.users).Count
    # v0.8.13: the report has no row for disabled accounts (lab, 22 Sep: 19 rows
    # for 21 users, the two missing were the two disabled ones). Coverage is
    # therefore rows / ENABLED users. accountEnabled null counts as enabled -
    # unknown is not disabled.
    $enabledRows = @($datasets.users | Where-Object { $_.accountEnabled -ne $false }).Count
    $reportRows  = @($datasets.authMethods).Count

    # Only from a COMPLETE users list. When the users call failed part-way
    # (simulator D16: page 2 of 3 returned 503) $datasets.users still holds
    # the pages that did arrive, and rows / partial-users is a confident
    # number with no meaning - it can even clear the 0.95 gate.
    if ((Test-DatasetOk 'users') -and $enabledRows -gt 0 -and $reportRows -gt 0) {
        $script:ReportCoverage = [math]::Round($reportRows / $enabledRows, 3)

        if ($script:ReportCoverage -gt 1.0) {
            # More rows than users: the report keeps rows for accounts deleted
            # since its last refresh (simulator D18). The counts below include
            # those ghosts; the engine should read this as "report is stale
            # around deletions", not as a data error. Informational.
            Add-CollectionWarning -Dataset 'authMethodsCoverage' -Kind 'info' -Message (
                "registration report has $reportRows rows for $enabledRows enabled users ($userRows total; coverage $($script:ReportCoverage)) - it still carries rows for deleted or since-disabled accounts; MFA counts include them")
        }
        if ($script:ReportCoverage -lt $MinReportCoverage) {
            # Deliberately a DIFFERENT dataset name from 'authMethods'. Using
            # the same one would mark the dataset failed and make
            # registrationReportAvailable false - losing the distinction
            # between "the report did not answer" and "the report answered
            # with a third of the rows". Those are different problems.
            Add-CollectionWarning -Dataset 'authMethodsCoverage' -Message (
                "registration report covers only $reportRows of $enabledRows enabled users ($userRows total) " +
                "(coverage $($script:ReportCoverage), minimum $MinReportCoverage). " +
                "Every MFA figure is therefore emitted as null, NOT as a count. " +
                "The report lags for hours after a tenant is licensed or accounts are created - re-run later.")
        } else {
            Write-Item "registration report coverage $($script:ReportCoverage) ($reportRows of $enabledRows enabled users, $userRows total)"
        }
    }

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $stamp = $started.ToString('yyyyMMdd-HHmmss')

    if ($Mode -eq 'Free') {
        $payload = [ordered]@{
            schemaVersion    = $SCHEMA_VERSION
            collectorVersion = $COLLECTOR_VERSION
            mode             = 'Free'
            collectedAt      = $started.ToString('o')
            durationSeconds  = [math]::Round(($finished - $started).TotalSeconds, 1)
            # Phase names and seconds only - no identifiers of any kind, so it
            # keeps the Free promise. Emitted because "use phaseTimings, not
            # guesses" is this file's own optimisation rule, and Free is the
            # mode clients actually run.
            phaseTimings     = $script:Timings
            # Dataset and HTTP status only. The message text stays on the
            # console: Graph errors embed the request URI (with object IDs on
            # per-object calls), request-ids and sometimes a UPN, so shipping
            # them would contradict the promise the aggregates keep.
            warnings         = @($script:Warnings | ForEach-Object {
                                  [ordered]@{ dataset = $_.dataset; kind = $_.kind; status = $_.status; code = $_.code } })
            aggregates       = (ConvertTo-FreeAggregate -D $datasets)
        }
        $file = Join-Path $OutputPath "veridan-scan-$stamp.json"
    }
    else {
        $payload = [ordered]@{
            schemaVersion    = $SCHEMA_VERSION
            collectorVersion = $COLLECTOR_VERSION
            mode             = 'Full'
            tenantId         = $datasets.tenant.tenantId
            collectedAt      = $started.ToString('o')
            completedAt      = $finished.ToString('o')
            durationSeconds  = [math]::Round(($finished - $started).TotalSeconds, 1)
            phaseTimings     = $script:Timings
            warnings         = @($script:Warnings)
            datasets         = $datasets
            aggregates       = (ConvertTo-FreeAggregate -D $datasets)   # same numbers, for cross-checking
        }
        if ($Anonymise) {
            $payload = ConvertTo-AnonymisedCollection -Data $payload
            Write-Item 'identifiers hashed (note: hashed records are still personal data)'
        }
        $file = Join-Path $OutputPath "veridan-collection-$stamp.json"
    }

    # Depth 12 truncated ScubaGear output silently - truncation is a warning,
    # not an error, so nobody noticed.
    $payload | ConvertTo-Json -Depth 40 | Set-Content -Path $file -Encoding UTF8
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    Set-Content -Path "$file.sha256" -Value $hash -Encoding UTF8

    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host ' Collection complete' -ForegroundColor Cyan
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host ("  users             : {0}" -f @($datasets.users).Count)
    Write-Host ("  groups            : {0}" -f @($datasets.groups).Count)
    Write-Host ("  role assignments  : {0}" -f @($datasets.roles).Count)
    Write-Host ("  applications      : {0}" -f @($datasets.applications).Count)
    Write-Host ("  service principals: {0}" -f @($datasets.servicePrincipals).Count)
    Write-Host ("  CA policies       : {0}" -f @($datasets.conditionalAccess.policies).Count)
    Write-Host ("  deleted users     : {0}" -f @($datasets.deletedUsers).Count)
    Write-Host ("  warnings          : {0}" -f $script:Warnings.Count) -ForegroundColor $(if ($script:Warnings.Count) { 'Yellow' } else { 'Green' })
    Write-Host ''
    Write-Host "  output : $file"
    Write-Host "  sha256 : $hash"
    Write-Host ''
    if ($Mode -eq 'Free') {
        Write-Host '  Free mode: this file contains counts only. No user, group' -ForegroundColor Green
        Write-Host '  or application records, and no identifiers of any kind.' -ForegroundColor Green
        Write-Host ''
    }
}
finally {
    if ($script:Sha) { $script:Sha.Dispose() }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

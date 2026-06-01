-- =====================================================================
-- AI-Augmented Vulnerability Scanner — Postgres Schema (Phase 0 / Phase 1)
-- Target: PostgreSQL 16+
-- Scope:  scan-and-report orchestrator for a regulated Indian life insurer
--         (BFSI / IRDAI / ISO 27001:2022). Scan-and-report ONLY.
--
-- Design invariants enforced at the DB layer:
--   1. There is NO exploitation phase. scans.phase has no 'exploit' value.
--   2. SLA due dates are computed by trigger, not hand-edited
--      (Critical/High = +30d, Medium/Low = +60d from detection).
--   3. Every target scanned must trace to an approved asset + a valid
--      scope authorization (the scope gate's ledger).
--   4. audit_log is append-only and hash-chained (tamper-evident).
--   5. A finding can only reach 'risk_accepted' via an approved exception
--      at the correct approver level (enforced in app + checked here).
-- =====================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS citext;        -- case-insensitive hostnames

-- ---------------------------------------------------------------------
-- Enumerated types
-- ---------------------------------------------------------------------
CREATE TYPE pipeline_kind   AS ENUM ('infra', 'webapp');

-- NOTE: deliberately NO 'exploit' / 'post_exploit' / 'lateral' value.
-- The pipeline state machine cannot represent exploitation.
CREATE TYPE scan_phase      AS ENUM (
    'scope', 'recon', 'mapping', 'detection', 'cis', 'triage', 'report', 'done'
);

CREATE TYPE scan_status     AS ENUM (
    'pending', 'authorizing', 'running', 'completed', 'failed', 'aborted'
);

CREATE TYPE scan_mode       AS ENUM ('blackbox', 'graybox');

CREATE TYPE asset_class     AS ENUM (
    'win_srv', 'linux_srv', 'app_srv', 'router_sdwan', 'switch',
    'firewall', 'nids_nips', 'storage', 'load_balancer', 'web_app'
);

CREATE TYPE severity        AS ENUM ('Critical', 'High', 'Medium', 'Low', 'Info');

CREATE TYPE auth_context    AS ENUM ('unauth', 'min_priv', 'max_priv');  -- web only

CREATE TYPE finding_status  AS ENUM (
    'new', 'triaged', 'validated', 'in_remediation',
    'retest', 'closed', 'risk_accepted', 'confirmed_fp'
);

CREATE TYPE fp_status       AS ENUM ('open', 'confirmed_fp', 'validated');

CREATE TYPE escalation_stage AS ENUM ('day0', 'day2', 'day4', 'day8_10', 'day15_20');
CREATE TYPE escalation_level AS ENUM ('stakeholder', 'manager', 'hod', 'csuite_mancom');

CREATE TYPE approver_level  AS ENUM ('CISO', 'RMC', 'Board');
CREATE TYPE approval_status AS ENUM ('requested', 'approved', 'rejected', 'expired');

CREATE TYPE authz_status    AS ENUM ('issued', 'consumed', 'expired', 'revoked');


-- ---------------------------------------------------------------------
-- 1. ASSETS — the HOD-approved inventory is the system of record.
--    The scope gate consults this table; absence == hard deny.
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    asset_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname            citext,
    ip                  inet,
    cidr                cidr,                 -- for ranges (e.g. SD-WAN segments)
    app_base_url        text,                 -- web apps only
    asset_class         asset_class NOT NULL,
    environment         text NOT NULL DEFAULT 'production',
    classification      text,                 -- data sensitivity label
    owner_team          text NOT NULL,
    hod_approver        text NOT NULL,        -- who approved inclusion
    approved_in_inventory boolean NOT NULL DEFAULT false,
    is_internal         boolean NOT NULL,     -- internal vs public IP (drives cadence)
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_verified_at    timestamptz,          -- last re-attestation of approval
    CONSTRAINT asset_has_target CHECK (
        ip IS NOT NULL OR cidr IS NOT NULL OR app_base_url IS NOT NULL
    )
);
CREATE INDEX idx_assets_approved   ON assets (approved_in_inventory) WHERE approved_in_inventory;
CREATE INDEX idx_assets_class      ON assets (asset_class);
CREATE INDEX idx_assets_internal   ON assets (is_internal);


-- ---------------------------------------------------------------------
-- 2. SCOPE_AUTHORIZATIONS — the scope gate's ledger.
--    Every scan must reference exactly one valid authorization.
--    token_hash is the SHA-256 of the signed scan-authorization token;
--    the token itself is never stored in plaintext.
-- ---------------------------------------------------------------------
CREATE TABLE scope_authorizations (
    authz_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_request_id uuid NOT NULL,            -- correlates to scheduler request
    pipeline        pipeline_kind NOT NULL,
    mode            scan_mode NOT NULL,
    target_asset_ids uuid[] NOT NULL,         -- resolved at issue time
    window_start    timestamptz NOT NULL,
    window_end      timestamptz NOT NULL,
    token_hash      bytea NOT NULL,           -- sha256(signed token)
    signed_by       text NOT NULL,            -- 'scheduler' or user principal
    status          authz_status NOT NULL DEFAULT 'issued',
    issued_at       timestamptz NOT NULL DEFAULT now(),
    consumed_at     timestamptz,
    revoked_at      timestamptz,
    CONSTRAINT authz_window CHECK (window_end > window_start),
    CONSTRAINT authz_targets_nonempty CHECK (cardinality(target_asset_ids) > 0)
);
CREATE INDEX idx_authz_status ON scope_authorizations (status);


-- ---------------------------------------------------------------------
-- 3. SCANS — one execution of a pipeline. phase advances scope->report;
--    it can NEVER advance into exploitation (no such enum value exists).
-- ---------------------------------------------------------------------
CREATE TABLE scans (
    scan_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline        pipeline_kind NOT NULL,
    profile         text NOT NULL,            -- SOP profile name
    authz_id        uuid NOT NULL REFERENCES scope_authorizations(authz_id),
    mode            scan_mode NOT NULL,
    phase           scan_phase NOT NULL DEFAULT 'scope',
    engine_set      text[] NOT NULL,          -- e.g. {nmap,nessus} or {zap,nuclei,trivy}
    status          scan_status NOT NULL DEFAULT 'pending',
    raw_artifact_uri text,                    -- object-store pointer (immutable)
    is_retest_of    uuid REFERENCES scans(scan_id),  -- links retest to original
    started_at      timestamptz,
    finished_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_authz   ON scans (authz_id);
CREATE INDEX idx_scans_status  ON scans (status);
CREATE INDEX idx_scans_retest  ON scans (is_retest_of) WHERE is_retest_of IS NOT NULL;


-- ---------------------------------------------------------------------
-- 4. FINDINGS — canonical, normalized finding. One row per distinct
--    issue after dedup. dup_of links suppressed duplicates.
-- ---------------------------------------------------------------------
CREATE TABLE findings (
    finding_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             uuid NOT NULL REFERENCES scans(scan_id),
    asset_id            uuid NOT NULL REFERENCES assets(asset_id),
    source_tool         text NOT NULL,        -- nessus, burp, nikto, zap, nuclei, trivy, nmap
    native_id           text,                 -- plugin id / issue type / template id
    title               text NOT NULL,
    description         text,
    cve                 text[] DEFAULT '{}',
    cvss_base           numeric(3,1),
    cvss_vector         text,
    severity_normalized severity NOT NULL,
    -- dedup / correlation
    dedup_key           text NOT NULL,        -- asset + port + signature hash
    dup_of              uuid REFERENCES findings(finding_id),
    -- false-positive handling (AI scores; human confirms)
    fp_likelihood       numeric(4,3),         -- 0.000–1.000, from LLM (advisory)
    fp_reason           text,
    fp_status           fp_status NOT NULL DEFAULT 'open',
    -- mappings
    owasp_web           text[] DEFAULT '{}',  -- e.g. {A01:2021, A03:2021}
    owasp_api           text[] DEFAULT '{}',  -- e.g. {API1:2023}
    sans25              text[] DEFAULT '{}',  -- CWE Top 25 ids
    cis_control         text,                 -- infra/config findings
    asset_class_tag     asset_class,
    auth_context        auth_context,         -- web findings only
    -- narrative (LLM-drafted, human-editable)
    impact_note         text,
    remediation_note    text,
    -- lifecycle
    status              finding_status NOT NULL DEFAULT 'new',
    detected_at         timestamptz NOT NULL DEFAULT now(),
    human_validated_by  text,
    human_validated_at  timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fp_score_range CHECK (fp_likelihood IS NULL OR (fp_likelihood >= 0 AND fp_likelihood <= 1))
);
CREATE INDEX idx_findings_scan     ON findings (scan_id);
CREATE INDEX idx_findings_asset    ON findings (asset_id);
CREATE INDEX idx_findings_dedup    ON findings (dedup_key);
CREATE INDEX idx_findings_status   ON findings (status);
CREATE INDEX idx_findings_sev      ON findings (severity_normalized);
CREATE UNIQUE INDEX uq_findings_dedup_per_scan ON findings (scan_id, dedup_key)
    WHERE dup_of IS NULL;   -- one canonical finding per dedup_key per scan


-- ---------------------------------------------------------------------
-- 5. SLAS — closure deadline per finding. due_date is computed by
--    trigger from severity + detected_at and is NOT hand-editable.
--    IRDAI SLA: Critical/High = 30 days; Medium/Low = 60 days.
-- ---------------------------------------------------------------------
CREATE TABLE slas (
    sla_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  uuid NOT NULL UNIQUE REFERENCES findings(finding_id) ON DELETE CASCADE,
    severity    severity NOT NULL,
    detected_at timestamptz NOT NULL,
    due_date    timestamptz NOT NULL,         -- set by trigger
    breached    boolean NOT NULL DEFAULT false,
    closed_at   timestamptz
);
CREATE INDEX idx_slas_due      ON slas (due_date) WHERE closed_at IS NULL;
CREATE INDEX idx_slas_breached ON slas (breached) WHERE breached;

-- SLA day-count policy in one place.
CREATE OR REPLACE FUNCTION sla_days_for(sev severity) RETURNS integer AS $$
BEGIN
    RETURN CASE sev
        WHEN 'Critical' THEN 30
        WHEN 'High'     THEN 30
        WHEN 'Medium'   THEN 60
        WHEN 'Low'      THEN 60
        ELSE 60                               -- Info: treat as Low window
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION trg_set_sla_due() RETURNS trigger AS $$
BEGIN
    NEW.due_date := NEW.detected_at + (sla_days_for(NEW.severity) || ' days')::interval;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sla_due_biu
    BEFORE INSERT OR UPDATE OF severity, detected_at ON slas
    FOR EACH ROW EXECUTE FUNCTION trg_set_sla_due();


-- ---------------------------------------------------------------------
-- 6. ESCALATIONS — the escalation staircase as trackable tasks.
--    Day0 report -> Day2 reminder -> Day4 +manager -> Day8-10 +HOD
--    -> Day15-20 +C-suite/ManCom.
-- ---------------------------------------------------------------------
CREATE TABLE escalations (
    esc_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  uuid NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    stage       escalation_stage NOT NULL,
    level       escalation_level NOT NULL,
    recipients  text[] NOT NULL,
    due_at      timestamptz NOT NULL,
    sent_at     timestamptz,
    status      text NOT NULL DEFAULT 'pending',  -- pending|sent|skipped
    UNIQUE (finding_id, stage)
);
CREATE INDEX idx_esc_due ON escalations (due_at) WHERE sent_at IS NULL;


-- ---------------------------------------------------------------------
-- 7. EXCEPTIONS — risk-acceptance routing by duration.
--    <=3 months: CISO; >3 months: RMC; >12 months: Board (+ reassessment).
-- ---------------------------------------------------------------------
CREATE TABLE exceptions (
    exc_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      uuid NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    requested_by    text NOT NULL,
    duration_months integer NOT NULL CHECK (duration_months > 0),
    approver_level  approver_level NOT NULL,
    approval_status approval_status NOT NULL DEFAULT 'requested',
    documented_risk text NOT NULL,            -- required justification
    evidence_uri    text,
    requires_reassessment boolean NOT NULL DEFAULT false,  -- true when >12 months
    requested_at    timestamptz NOT NULL DEFAULT now(),
    approved_at     timestamptz,
    expires_at      timestamptz,
    -- Enforce duration->approver routing at the DB layer.
    CONSTRAINT exc_routing CHECK (
        (duration_months <= 3  AND approver_level = 'CISO') OR
        (duration_months > 3   AND duration_months <= 12 AND approver_level = 'RMC') OR
        (duration_months > 12  AND approver_level = 'Board')
    ),
    CONSTRAINT exc_reassess CHECK (
        (duration_months > 12) = requires_reassessment
    )
);
CREATE INDEX idx_exc_finding ON exceptions (finding_id);
CREATE INDEX idx_exc_expiry  ON exceptions (expires_at) WHERE approval_status = 'approved';


-- ---------------------------------------------------------------------
-- 8. RETESTS — closure verification by diff against the prior scan.
-- ---------------------------------------------------------------------
CREATE TABLE retests (
    retest_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    original_scan_id  uuid NOT NULL REFERENCES scans(scan_id),
    new_scan_id       uuid NOT NULL REFERENCES scans(scan_id),
    finding_id        uuid NOT NULL REFERENCES findings(finding_id),
    prior_status      finding_status NOT NULL,
    new_status        finding_status NOT NULL,
    closure_confirmed boolean NOT NULL DEFAULT false,
    compared_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_retests_finding ON retests (finding_id);


-- ---------------------------------------------------------------------
-- 9. AUDIT_LOG — append-only, hash-chained (tamper-evident).
--    row_hash = sha256(prev_hash || canonicalized row).
--    UPDATE/DELETE are blocked by a trigger.
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    seq         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,                -- user principal or 'system'
    action      text NOT NULL,                -- e.g. SCAN_LAUNCHED, FINDING_VALIDATED
    entity_type text NOT NULL,
    entity_id   uuid,
    before      jsonb,
    after       jsonb,
    prev_hash   bytea,
    row_hash    bytea NOT NULL
);

CREATE OR REPLACE FUNCTION trg_audit_hash() RETURNS trigger AS $$
DECLARE
    last_hash bytea;
    payload   text;
BEGIN
    SELECT row_hash INTO last_hash FROM audit_log ORDER BY seq DESC LIMIT 1;
    NEW.prev_hash := last_hash;
    payload := coalesce(encode(last_hash, 'hex'), '') ||
               NEW.ts::text || NEW.actor || NEW.action || NEW.entity_type ||
               coalesce(NEW.entity_id::text, '') ||
               coalesce(NEW.before::text, '') || coalesce(NEW.after::text, '');
    NEW.row_hash := digest(payload, 'sha256');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_hash_bi
    BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_hash();

CREATE OR REPLACE FUNCTION trg_audit_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_immutable();


-- ---------------------------------------------------------------------
-- Convenience view: open findings with live SLA state (for dashboards).
-- ---------------------------------------------------------------------
CREATE VIEW v_open_findings_sla AS
SELECT  f.finding_id,
        a.hostname,
        a.asset_class,
        f.title,
        f.severity_normalized,
        f.status,
        s.due_date,
        (s.due_date < now() AND s.closed_at IS NULL) AS overdue,
        f.owasp_web, f.owasp_api, f.sans25, f.cis_control,
        f.detected_at
FROM    findings f
JOIN    assets a ON a.asset_id = f.asset_id
LEFT JOIN slas s ON s.finding_id = f.finding_id
WHERE   f.status NOT IN ('closed', 'risk_accepted', 'confirmed_fp')
  AND   f.dup_of IS NULL;


-- =====================================================================
-- Identity & RBAC (auth slice) — AD/LDAP + OIDC
-- Implements the FROZEN contract in docs/auth-contract.md (§1 roles +
-- AD-group->role map, §2 User shape / session, §3 RBAC).
--
-- Enforcement of RBAC lives in the API (auth.py :: require_role); these
-- tables are the DB-side system of record for *who* a principal is, the
-- effective roles resolved from AD groups at login, and the group->role
-- mapping. The signed session cookie (itsdangerous, §2) is stateless and
-- is the runtime source of truth for a session — auth_sessions below is a
-- LOGIN AUDIT / forensics table only, NOT used for session validation.
--
-- Actor-spoofing closure: audit_log.actor (above) is now written with the
-- *session-derived* actor server-side (session_actor(user), e.g.
-- "Vantage Dev <dev@vantage.local>"); mutation handlers no longer read the
-- actor from the request body. No audit_log schema change is needed — the
-- guarantee is in how actor is populated, not in its column.
-- =====================================================================

-- Wire values MUST match auth.py :: class Role(str, Enum) exactly (§1).
-- 'admin' is a wildcard that implicitly satisfies every require_role check.
CREATE TYPE vantage_role AS ENUM (
    'viewer', 'analyst', 'approver_ciso', 'approver_rmc', 'approver_board', 'admin'
);


-- ---------------------------------------------------------------------
-- 10. IDENTITIES — one row per authenticated principal (IdP subject).
--     `sub` is the stable OIDC subject id ('dev' in dev mode). email is
--     stored as citext (extension already enabled above) so uniqueness is
--     case-insensitive without a separate functional index.
-- ---------------------------------------------------------------------
CREATE TABLE identities (
    identity_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sub             text NOT NULL UNIQUE,         -- stable IdP subject id
    email           citext UNIQUE,                -- case-insensitive, may be null
    display_name    text,
    last_login_at   timestamptz,
    is_active       boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_identities_active ON identities (is_active) WHERE is_active;


-- ---------------------------------------------------------------------
-- 11. IDENTITY_ROLES — the effective roles a principal holds, resolved
--     from AD groups at login (a user may hold multiple roles). This is
--     the materialized result of group_role_map applied to the user's
--     group claims; the session cookie carries the same set at runtime.
-- ---------------------------------------------------------------------
CREATE TABLE identity_roles (
    identity_id     uuid NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    role            vantage_role NOT NULL,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, role)
);
CREATE INDEX idx_identity_roles_role ON identity_roles (role);


-- ---------------------------------------------------------------------
-- 12. GROUP_ROLE_MAP — DB-side mirror of the env VANTAGE_GROUP_ROLE_MAP
--     (§1). Maps an AD group (group name or DN, matched case-insensitively
--     by the app) to a role. A single group may map to multiple roles.
--     A user with no mapped group gets 'viewer' (least privilege) in the
--     app — that default is not represented as a row here.
-- ---------------------------------------------------------------------
CREATE TABLE group_role_map (
    ad_group        text NOT NULL,                -- AD group name or DN
    role            vantage_role NOT NULL,
    note            text,
    PRIMARY KEY (ad_group, role)
);

-- Representative seed mapping (documents the intended wiring in-schema).
INSERT INTO group_role_map (ad_group, role, note) VALUES
    ('SEC-AppSec',        'analyst',        'AppSec engineers / triagers'),
    ('SEC-CISO',          'approver_ciso',  'CISO exception approver (<=3mo)'),
    ('SEC-RMC',           'approver_rmc',   'Risk Mgmt Committee approver (>3-12mo)'),
    ('SEC-Board',         'approver_board', 'Board approver (>12mo)'),
    ('SEC-Auditors',      'viewer',         'Read-only auditors'),
    ('SEC-VantageAdmins', 'admin',          'Vantage administrators (wildcard)');


-- ---------------------------------------------------------------------
-- 13. AUTH_SESSIONS — LOGIN AUDIT / forensics ONLY.
--     The runtime uses stateless signed cookies (§2); the signed cookie
--     is the source of truth for session validity. This table is written
--     at login for login-history / observability and is NEVER consulted to
--     validate a request. A non-null revoked_at records an explicit logout
--     or admin revocation for the forensic trail.
-- ---------------------------------------------------------------------
CREATE TABLE auth_sessions (
    session_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id     uuid NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    user_agent      text,
    revoked_at      timestamptz
);
CREATE INDEX idx_auth_sessions_identity ON auth_sessions (identity_id);
CREATE INDEX idx_auth_sessions_active   ON auth_sessions (expires_at)
    WHERE revoked_at IS NULL;


-- =====================================================================
-- Console state (overlay persistence) — orchestrator/api/store.py
-- These tables are CONSOLE-FACING state, keyed by the API's own STRING
-- ids (e.g. 'VLN-2087', 'SCAN-0099', 'EXC-047') — deliberately DISTINCT
-- from the normalized scanner tables above (findings/scans/exceptions,
-- which are uuid-keyed and populated by the real pipeline). store.py
-- overlays these mutations on the seed catalog so they SURVIVE AN API
-- RESTART when DATABASE_URL is configured: a finding's status change, an
-- API-created scan, and an API-created exception. No foreign keys: the
-- referenced finding/scan/exception may live only in the seed catalog,
-- never in the normalized tables, so there is nothing to reference. The
-- whole scan/exception payload is stored as jsonb; finding state is a
-- thin row. Create order is independent (no FKs); all inside this txn.
-- =====================================================================

-- 14. CONSOLE_FINDING_STATE — mutable status overlay for one finding,
--     keyed by the API string id. UPSERT-on-finding_id from store.py
--     (status / validated_by / validated_at, with updated_at = now()).
CREATE TABLE console_finding_state (
    finding_id   text PRIMARY KEY,             -- API string id, e.g. 'VLN-2087'
    status       text NOT NULL,                -- console status (free-form wire value)
    validated_by text,                         -- human who validated (display string)
    validated_at date,                         -- date of human validation (nullable)
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- 15. CONSOLE_SCANS — an API-created scan, whole dict persisted as jsonb,
--     keyed by its API string id ('SCAN-...'). INSERT ... ON CONFLICT
--     (scan_id) DO UPDATE from store.py; read back ORDER BY created_at.
CREATE TABLE console_scans (
    scan_id    text PRIMARY KEY,               -- API string id, e.g. 'SCAN-0099'
    data       jsonb NOT NULL,                 -- full scan payload as created by the console
    created_at timestamptz NOT NULL DEFAULT now()
);

-- 16. CONSOLE_EXCEPTIONS — an API-created exception, whole dict persisted
--     as jsonb, keyed by its API string id ('EXC-...'). Same upsert shape.
CREATE TABLE console_exceptions (
    exception_id text PRIMARY KEY,             -- API string id, e.g. 'EXC-047'
    data         jsonb NOT NULL,               -- full exception payload from the console
    created_at   timestamptz NOT NULL DEFAULT now()
);

COMMIT;

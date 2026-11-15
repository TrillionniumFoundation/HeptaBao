-- Operator-installed PostgreSQL 17 provider contract. Execute as a dedicated
-- privileged schema owner; grant only the five functions to the login manager.
-- No API caller is allowed to supply SQL. The manager and group allowlist are
-- provisioned separately, never inferred from an API request or a role name.
BEGIN;
CREATE SCHEMA heptabao_provider;
REVOKE ALL ON SCHEMA heptabao_provider FROM PUBLIC;
CREATE TABLE heptabao_provider.allowed_groups (
    manager name NOT NULL, group_name name NOT NULL, PRIMARY KEY (manager, group_name)
);
CREATE TABLE heptabao_provider.fences (
    manager name NOT NULL,
    fence_id text NOT NULL CHECK(fence_id ~ '^hbf1:[0-9a-f]{64}$'),
    last_seq bigint NOT NULL CHECK(last_seq >= 0),
    PRIMARY KEY(manager, fence_id)
);
CREATE TABLE heptabao_provider.leases (
    manager name NOT NULL,
    fence_id text NOT NULL CHECK(fence_id ~ '^hbf1:[0-9a-f]{64}$'),
    lease_id text NOT NULL,
    username name NOT NULL UNIQUE,
    seq bigint NOT NULL CHECK(seq > 0),
    action text NOT NULL CHECK(action IN ('issue','renew','revoke')),
    expires bigint NOT NULL,
    group_name name NOT NULL,
    request_digest text NOT NULL,
    password_digest text,
    role_oid oid,
    group_oid oid,
    payload_digest text NOT NULL,
    PRIMARY KEY(manager, lease_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA heptabao_provider FROM PUBLIC;

CREATE FUNCTION heptabao_provider.protocol() RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT 'heptabao-postgresql-provider-v2'::text $$;
REVOKE ALL ON FUNCTION heptabao_provider.protocol() FROM PUBLIC;

CREATE FUNCTION heptabao_provider.observe(p_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.leases%ROWTYPE; r record; sessions bigint;
BEGIN
    SELECT * INTO l FROM heptabao_provider.leases WHERE manager = session_user AND lease_id = p_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('found',false); END IF;
    SELECT oid, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
           rolvaliduntil, rolpassword INTO r FROM pg_authid WHERE rolname=l.username;
    SELECT count(*) INTO sessions FROM pg_stat_activity WHERE usename=l.username;
    RETURN jsonb_build_object('found',true,'fence_id',l.fence_id,'lease_id',l.lease_id,'username',l.username,
        'seq',l.seq,'action',l.action,'expires',l.expires,'request_digest',l.request_digest,
        'login',COALESCE(r.rolcanlogin,false),'active_sessions',sessions,
        'controlled',r.oid=l.role_oid AND r.rolpassword IS NOT NULL
            AND (SELECT count(*)=1 AND bool_and(roleid=l.group_oid) FROM pg_auth_members WHERE member=r.oid)
            AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
            AND encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex')=l.password_digest
            AND extract(epoch FROM r.rolvaliduntil)::bigint=l.expires);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.observe(text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.retired(p_fence text,p_id text,p_name text,p_seq bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE floor bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq < 1 THEN
        RAISE EXCEPTION 'invalid provider retirement query';
    END IF;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN COALESCE(floor,0) >= p_seq
       AND NOT EXISTS(
           SELECT 1 FROM heptabao_provider.leases
            WHERE manager=session_user AND lease_id=p_id
       )
       AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.retired(text,text,text,bigint) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.apply(
    p_fence text,p_id text,p_name text,p_seq bigint,p_action text,p_expires bigint,
    p_group text,p_password text,p_digest text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.leases%ROWTYPE; existing boolean; expiry text; pid integer;
        group_ok boolean; payload_hash text; floor bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL OR p_action IS NULL
       OR p_expires IS NULL OR p_group IS NULL OR p_password IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq<1
       OR p_action NOT IN ('issue','renew','revoke') OR p_expires<0
       OR p_digest !~ '^[0-9a-f]{64}$' OR length(p_group)>63 OR p_group='' THEN
        RAISE EXCEPTION 'invalid provider operation';
    END IF;
    payload_hash := encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_name,p_seq,p_action,p_expires,p_group,p_password,p_digest)::text,
        'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
        VALUES(session_user,p_fence,0) ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO l FROM heptabao_provider.leases
      WHERE manager=session_user AND lease_id=p_id FOR UPDATE;
    existing := FOUND;

    IF existing THEN
        IF l.fence_id<>p_fence OR l.username<>p_name OR l.group_name<>p_group OR p_seq<l.seq THEN
            RAISE EXCEPTION 'provider identity or fence mismatch';
        END IF;
        IF p_seq=l.seq THEN
            IF floor<>p_seq OR l.request_digest<>p_digest OR l.payload_digest<>payload_hash
               OR l.action<>p_action OR l.expires<>p_expires THEN
                RAISE EXCEPTION 'provider semantic conflict';
            END IF;
            RETURN heptabao_provider.observe(p_id);
        END IF;
    END IF;

    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale operation';
    END IF;
    IF existing AND l.action='revoke' AND p_action<>'revoke' THEN
        RAISE EXCEPTION 'provider resurrection rejected';
    END IF;

    IF p_action='issue' THEN
        IF existing OR p_password !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'provider issue rejected'; END IF;
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN RAISE EXCEPTION 'unowned role collision'; END IF;
        SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcanlogin)
          INTO group_ok FROM pg_roles WHERE rolname=p_group;
        IF NOT COALESCE(group_ok,false) OR p_group LIKE 'pg\_%' OR NOT EXISTS(
            SELECT 1 FROM heptabao_provider.allowed_groups WHERE manager=session_user AND group_name=p_group
        ) THEN RAISE EXCEPTION 'provider group not independently enrolled'; END IF;
    ELSIF p_action='renew' THEN
        IF NOT existing OR l.action='revoke' OR p_expires<=l.expires OR p_password<>'' THEN
            RAISE EXCEPTION 'provider renewal rejected';
        END IF;
        IF (heptabao_provider.observe(p_id)->>'controlled')::boolean IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'provider role drift';
        END IF;
    ELSE
        IF p_password<>'' OR p_expires<>0 THEN RAISE EXCEPTION 'invalid revocation payload'; END IF;
        IF NOT existing AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
            RAISE EXCEPTION 'unowned role collision';
        END IF;
    END IF;

    IF p_action<>'revoke' THEN
        IF p_expires<=extract(epoch FROM clock_timestamp())::bigint
           OR p_expires>extract(epoch FROM clock_timestamp())::bigint+86400 THEN
            RAISE EXCEPTION 'provider TTL outside bounds';
        END IF;
        expiry:=to_char(to_timestamp(p_expires) AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || '+00';
        IF p_action='issue' THEN
            EXECUTE format(
                'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD %L VALID UNTIL %L',
                p_name,p_password,expiry);
            EXECUTE format('GRANT %I TO %I',p_group,p_name);
        ELSE
            EXECUTE format('ALTER ROLE %I VALID UNTIL %L',p_name,expiry);
        END IF;
    ELSIF existing AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
        IF (heptabao_provider.observe(p_id)->>'controlled')::boolean IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'provider role identity or ownership drift; quarantine required';
        END IF;
        EXECUTE format('ALTER ROLE %I NOLOGIN VALID UNTIL %L',p_name,'1970-01-01 00:00:00+00');
        FOR pid IN SELECT a.pid FROM pg_stat_activity a WHERE a.usename=p_name LOOP
            PERFORM pg_terminate_backend(pid,1000);
        END LOOP;
    END IF;

    INSERT INTO heptabao_provider.leases(
        manager,fence_id,lease_id,username,seq,action,expires,group_name,request_digest,
        password_digest,role_oid,group_oid,payload_digest)
        VALUES(session_user,p_fence,p_id,p_name,p_seq,p_action,p_expires,p_group,p_digest,
            (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex') FROM pg_authid WHERE rolname=p_name),
            (SELECT oid FROM pg_roles WHERE rolname=p_name),
            (SELECT oid FROM pg_roles WHERE rolname=p_group),payload_hash)
        ON CONFLICT(manager,lease_id) DO UPDATE SET
            fence_id=EXCLUDED.fence_id,seq=EXCLUDED.seq,action=EXCLUDED.action,
            expires=EXCLUDED.expires,request_digest=EXCLUDED.request_digest,
            password_digest=EXCLUDED.password_digest,role_oid=EXCLUDED.role_oid,
            group_oid=EXCLUDED.group_oid,payload_digest=EXCLUDED.payload_digest;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.observe(p_id);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.apply(text,text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.retire(p_fence text,p_id text,p_name text,p_seq bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.leases%ROWTYPE; floor bigint; sessions bigint; role record;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq<1 THEN
        RAISE EXCEPTION 'invalid provider retirement';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(session_user || ':' || p_fence,0));
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    IF NOT FOUND OR floor<p_seq THEN RAISE EXCEPTION 'provider retirement fence missing'; END IF;

    SELECT * INTO l FROM heptabao_provider.leases
      WHERE manager=session_user AND lease_id=p_id FOR UPDATE;
    IF NOT FOUND THEN
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
            RAISE EXCEPTION 'provider retirement ledger missing while role remains';
        END IF;
        RETURN true;
    END IF;
    IF l.fence_id<>p_fence OR l.username<>p_name OR l.seq<>p_seq OR l.action<>'revoke' THEN
        RAISE EXCEPTION 'provider retirement identity mismatch';
    END IF;
    SELECT oid,rolcanlogin INTO role FROM pg_authid WHERE rolname=p_name;
    IF FOUND THEN
        SELECT count(*) INTO sessions FROM pg_stat_activity WHERE usename=p_name;
        IF role.oid<>l.role_oid OR role.rolcanlogin OR sessions<>0 THEN
            RAISE EXCEPTION 'provider role is not safe to retire';
        END IF;
        -- Global fence ordering now prevents every older issue/renew from
        -- re-entering after this point, so the NOLOGIN role no longer has to be
        -- retained as the permanent anti-replay tombstone. DROP ROLE remains
        -- deliberately fail-closed if application-owned objects or grants make
        -- retirement unsafe; no DROP OWNED/REASSIGN OWNED is attempted.
        EXECUTE format('DROP ROLE %I',p_name);
    END IF;
    DELETE FROM heptabao_provider.leases
      WHERE manager=session_user AND lease_id=p_id;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.retire(text,text,text,bigint) FROM PUBLIC;

COMMIT;
-- Explicit example, after CREATE ROLE hb_manager LOGIN PASSWORD ...:
-- GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.observe(text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retired(text,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply(text,text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retire(text,text,text,bigint) TO hb_manager;
-- INSERT INTO heptabao_provider.allowed_groups VALUES ('hb_manager','app_reader');

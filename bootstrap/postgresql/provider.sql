-- Operator-installed PostgreSQL 17 provider contract. Execute as a dedicated
-- privileged schema owner; grant only the three functions to the login manager.
-- No API caller is allowed to supply SQL. The manager and group allowlist are
-- provisioned separately, never inferred from an API request or a role name.
BEGIN;
CREATE SCHEMA heptabao_provider;
REVOKE ALL ON SCHEMA heptabao_provider FROM PUBLIC;
CREATE TABLE heptabao_provider.allowed_groups (
    manager name NOT NULL, group_name name NOT NULL, PRIMARY KEY (manager, group_name)
);
CREATE TABLE heptabao_provider.leases (
    manager name NOT NULL,
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
AS $$ SELECT 'heptabao-postgresql-provider-v1'::text $$;
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
    RETURN jsonb_build_object('found',true,'lease_id',l.lease_id,'username',l.username,
        'seq',l.seq,'action',l.action,'expires',l.expires,'request_digest',l.request_digest,
        'login',COALESCE(r.rolcanlogin,false),'active_sessions',sessions,
        'controlled',r.oid=l.role_oid AND r.rolpassword IS NOT NULL
            AND (SELECT count(*)=1 AND bool_and(roleid=l.group_oid) FROM pg_auth_members WHERE member=r.oid)
            AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
            AND encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex')=l.password_digest
            AND extract(epoch FROM r.rolvaliduntil)::bigint=l.expires);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.observe(text) FROM PUBLIC;
CREATE FUNCTION heptabao_provider.apply(p_id text,p_name text,p_seq bigint,p_action text,p_expires bigint,p_group text,p_password text,p_digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.leases%ROWTYPE; existing boolean; expiry text; pid integer; group_ok boolean; payload_hash text;
BEGIN
    IF p_id IS NULL OR p_name IS NULL OR p_seq IS NULL OR p_action IS NULL
       OR p_expires IS NULL OR p_group IS NULL OR p_password IS NULL OR p_digest IS NULL
       OR p_id !~ '^hb1:[0-9a-f]{64}$' OR p_name !~ '^hbp_[0-9a-f]{32}$'
       OR p_seq<1 OR p_action NOT IN ('issue','renew','revoke') OR p_expires<0
       OR p_digest !~ '^[0-9a-f]{64}$' OR length(p_group)>63 OR p_group='' THEN
        RAISE EXCEPTION 'invalid provider operation';
    END IF;
    payload_hash := encode(sha256(convert_to(jsonb_build_array(p_id,p_name,p_seq,p_action,p_expires,p_group,p_password,p_digest)::text,'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(hashtextextended(session_user || ':' || p_id,0));
    SELECT * INTO l FROM heptabao_provider.leases WHERE manager=session_user AND lease_id=p_id FOR UPDATE;
    existing := FOUND;
    IF existing THEN
        IF l.username<>p_name OR l.group_name<>p_group OR p_seq<l.seq THEN RAISE EXCEPTION 'provider identity or fence mismatch'; END IF;
        IF p_seq=l.seq THEN
            IF l.request_digest<>p_digest OR l.payload_digest<>payload_hash OR l.action<>p_action OR l.expires<>p_expires THEN RAISE EXCEPTION 'provider semantic conflict'; END IF;
            RETURN heptabao_provider.observe(p_id);
        END IF;
        IF (p_action<>'revoke' AND p_seq<>l.seq+1) OR (l.action='revoke' AND p_action<>'revoke') THEN RAISE EXCEPTION 'provider sequence or resurrection rejected'; END IF;
    END IF;
    IF p_action='issue' THEN
        IF existing OR p_seq<>1 OR p_password !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'provider issue rejected'; END IF;
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN RAISE EXCEPTION 'unowned role collision'; END IF;
        SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolcanlogin)
          INTO group_ok FROM pg_roles WHERE rolname=p_group;
        IF NOT COALESCE(group_ok,false) OR p_group LIKE 'pg\_%' OR NOT EXISTS(
            SELECT 1 FROM heptabao_provider.allowed_groups WHERE manager=session_user AND group_name=p_group
        ) THEN RAISE EXCEPTION 'provider group not independently enrolled'; END IF;
    ELSIF p_action='renew' THEN
        IF NOT existing OR l.action='revoke' OR p_expires<=l.expires OR p_password<>'' THEN RAISE EXCEPTION 'provider renewal rejected'; END IF;
        IF (heptabao_provider.observe(p_id)->>'controlled')::boolean IS DISTINCT FROM true THEN RAISE EXCEPTION 'provider role drift'; END IF;
    ELSE
        IF p_password<>'' OR p_expires<>0 THEN RAISE EXCEPTION 'invalid revocation payload'; END IF;
        IF NOT existing AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN RAISE EXCEPTION 'unowned role collision'; END IF;
    END IF;
    IF p_action<>'revoke' THEN
        IF p_expires<=extract(epoch FROM clock_timestamp())::bigint OR p_expires>extract(epoch FROM clock_timestamp())::bigint+86400 THEN RAISE EXCEPTION 'provider TTL outside bounds'; END IF;
        expiry:=to_char(to_timestamp(p_expires) AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || '+00';
        IF p_action='issue' THEN
            EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD %L VALID UNTIL %L',p_name,p_password,expiry);
            EXECUTE format('GRANT %I TO %I',p_group,p_name);
        ELSE
            EXECUTE format('ALTER ROLE %I VALID UNTIL %L',p_name,expiry);
        END IF;
    ELSIF existing AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
        IF (heptabao_provider.observe(p_id)->>'controlled')::boolean IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'provider role identity or ownership drift; quarantine required';
        END IF;
        -- Deliberate bounded profile: retain a NOLOGIN tombstone rather than
        -- DROP OWNED on a potentially changed database. New sessions are denied
        -- and existing sessions are terminated before service completion.
        EXECUTE format('ALTER ROLE %I NOLOGIN VALID UNTIL %L',p_name,'1970-01-01 00:00:00+00');
        FOR pid IN SELECT a.pid FROM pg_stat_activity a WHERE a.usename=p_name LOOP
            PERFORM pg_terminate_backend(pid,1000);
        END LOOP;
    END IF;
    INSERT INTO heptabao_provider.leases(manager,lease_id,username,seq,action,expires,group_name,request_digest,password_digest,role_oid,group_oid,payload_digest)
        VALUES(session_user,p_id,p_name,p_seq,p_action,p_expires,p_group,p_digest,
            (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex') FROM pg_authid WHERE rolname=p_name),
            (SELECT oid FROM pg_roles WHERE rolname=p_name),
            (SELECT oid FROM pg_roles WHERE rolname=p_group),payload_hash)
        ON CONFLICT(manager,lease_id) DO UPDATE SET seq=EXCLUDED.seq,action=EXCLUDED.action,
            expires=EXCLUDED.expires,request_digest=EXCLUDED.request_digest,password_digest=EXCLUDED.password_digest,
            role_oid=EXCLUDED.role_oid,group_oid=EXCLUDED.group_oid,payload_digest=EXCLUDED.payload_digest;
    RETURN heptabao_provider.observe(p_id);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.apply(text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;
COMMIT;
-- Explicit example, after CREATE ROLE hb_manager LOGIN PASSWORD ...:
-- GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.observe(text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply(text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- INSERT INTO heptabao_provider.allowed_groups VALUES ('hb_manager','app_reader');

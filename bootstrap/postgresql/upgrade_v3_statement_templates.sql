-- Forward-only upgrade from the exact v2 provider contract.
BEGIN;
DO $$
BEGIN
    IF heptabao_provider.protocol() <> 'heptabao-postgresql-provider-v2' THEN
        RAISE EXCEPTION 'unexpected PostgreSQL provider protocol';
    END IF;
END $$;

-- PostgreSQL statement-template extension. The statement text is supplied only
-- to this bounded transaction; the durable provider row retains digests.
CREATE TABLE heptabao_provider.statement_leases (
    manager name NOT NULL,
    fence_id text NOT NULL CHECK(fence_id ~ '^hbf1:[0-9a-f]{64}$'),
    lease_id text NOT NULL CHECK(lease_id ~ '^hb1:[0-9a-f]{64}$'),
    username name NOT NULL UNIQUE,
    seq bigint NOT NULL CHECK(seq > 0),
    action text NOT NULL CHECK(action IN ('issue','renew','revoke')),
    expires bigint NOT NULL,
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    statements_digest text NOT NULL CHECK(statements_digest ~ '^[0-9a-f]{64}$'),
    password_digest text,
    role_oid oid,
    payload_digest text NOT NULL CHECK(payload_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(manager, lease_id)
);
REVOKE ALL ON TABLE heptabao_provider.statement_leases FROM PUBLIC;

CREATE FUNCTION heptabao_provider.statement_protocol() RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT 'heptabao-postgresql-statements-v1'::text $$;
REVOKE ALL ON FUNCTION heptabao_provider.statement_protocol() FROM PUBLIC;

CREATE FUNCTION heptabao_provider.observe_statement(p_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.statement_leases%ROWTYPE; r record;
        role_found boolean; sessions bigint; controlled boolean; terminal boolean;
BEGIN
    SELECT * INTO l FROM heptabao_provider.statement_leases
      WHERE manager=session_user AND lease_id=p_id;
    IF NOT FOUND THEN RETURN jsonb_build_object('found',false); END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,
           rolbypassrls,rolvaliduntil,rolpassword INTO r
      FROM pg_authid WHERE rolname=l.username;
    role_found:=FOUND;
    SELECT count(*) INTO sessions FROM pg_stat_activity WHERE usename=l.username;
    controlled:=role_found AND r.oid=l.role_oid AND r.rolcanlogin
       AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
                OR r.rolreplication OR r.rolbypassrls)
       AND r.rolpassword IS NOT NULL
       AND encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex')=l.password_digest
       AND extract(epoch FROM r.rolvaliduntil)::bigint=l.expires;
    terminal:=l.action='revoke' AND (
       NOT role_found OR (NOT COALESCE(r.rolcanlogin,false) AND sessions=0));
    RETURN jsonb_build_object(
       'found',true,'fence_id',l.fence_id,'lease_id',l.lease_id,
       'username',l.username,'seq',l.seq,'action',l.action,'expires',l.expires,
       'request_digest',l.request_digest,'statements_digest',l.statements_digest,
       'controlled',controlled,'terminal',terminal,'role_present',role_found,
       'login',COALESCE(r.rolcanlogin,false),'active_sessions',sessions);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.observe_statement(text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.statement_retired(
    p_fence text,p_id text,p_name text,p_seq bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE floor bigint; r record; sessions bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq<1 THEN
        RAISE EXCEPTION 'invalid statement retirement query';
    END IF;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence;
    IF COALESCE(floor,0)<p_seq OR EXISTS(
       SELECT 1 FROM heptabao_provider.statement_leases
        WHERE manager=session_user AND lease_id=p_id) THEN
        RETURN false;
    END IF;
    SELECT rolcanlogin INTO r FROM pg_authid WHERE rolname=p_name;
    IF NOT FOUND THEN RETURN true; END IF;
    SELECT count(*) INTO sessions FROM pg_stat_activity WHERE usename=p_name;
    RETURN NOT r.rolcanlogin AND sessions=0;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.statement_retired(text,text,text,bigint) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.default_statement_revoke(p_name name) RETURNS boolean
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE schema_name name; schema_count integer:=0;
BEGIN
    IF p_name IS NULL OR p_name::text !~ '^hbp_[0-9a-f]{32}$' THEN
        RAISE EXCEPTION 'invalid generated database role';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
        RETURN true;
    END IF;
    EXECUTE format('ALTER ROLE %I NOLOGIN VALID UNTIL %L',p_name,'1970-01-01 00:00:00+00');
    PERFORM pg_terminate_backend(pid) FROM pg_stat_activity
      WHERE usename=p_name AND pid<>pg_backend_pid();
    FOR schema_name IN
        SELECT DISTINCT table_schema::name
          FROM information_schema.role_column_grants WHERE grantee=p_name
        UNION
        SELECT DISTINCT table_schema::name
          FROM information_schema.table_privileges WHERE grantee=p_name
    LOOP
        schema_count:=schema_count+1;
        IF schema_count>64 THEN RAISE EXCEPTION 'role schema grant count exceeds bound'; END IF;
        EXECUTE format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM %I',schema_name,p_name);
        EXECUTE format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM %I',schema_name,p_name);
        EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM %I',schema_name,p_name);
    END LOOP;
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I',p_name);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I',p_name);
    EXECUTE format('REVOKE USAGE ON SCHEMA public FROM %I',p_name);
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I',current_database(),p_name);
    EXECUTE format('DROP ROLE IF EXISTS %I',p_name);
    RETURN NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.default_statement_revoke(name) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.apply_statements(
    p_fence text,p_id text,p_name text,p_seq bigint,p_action text,p_expires bigint,
    p_password text,p_digest text,p_statements text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.statement_leases%ROWTYPE; r record;
        existing boolean; role_found boolean; statement text; rendered text;
        expiration text; sessions bigint; payload_hash text; statement_hash text;
        floor bigint; total_bytes bigint; identity_count bigint; observed jsonb;
        parsed_statements jsonb;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_action IS NULL OR p_expires IS NULL OR p_password IS NULL
       OR p_digest IS NULL OR p_statements IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq<1
       OR p_action NOT IN ('issue','renew','revoke')
       OR p_digest !~ '^[0-9a-f]{64}$'
       OR octet_length(p_statements)>69632 THEN
        RAISE EXCEPTION 'invalid statement provider operation';
    END IF;
    BEGIN
        parsed_statements:=p_statements::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'invalid statement provider operation';
    END;
    IF jsonb_typeof(parsed_statements)<>'array'
       OR jsonb_array_length(parsed_statements)<1
       OR jsonb_array_length(parsed_statements)>64
       OR EXISTS(SELECT 1 FROM jsonb_array_elements(parsed_statements) value
                   WHERE jsonb_typeof(value)<>'string') THEN
        RAISE EXCEPTION 'invalid statement provider operation';
    END IF;
    SELECT COALESCE(sum(octet_length(value)),0) INTO total_bytes
      FROM jsonb_array_elements_text(parsed_statements) value;
    IF total_bytes>65536 OR EXISTS(
       SELECT 1 FROM jsonb_array_elements_text(parsed_statements) value
        WHERE value='' OR octet_length(value)>16384) THEN
        RAISE EXCEPTION 'statement provider payload outside bounds';
    END IF;
    IF (p_action='issue' AND (p_password !~ '^[0-9a-f]{64}$' OR p_expires<1))
       OR (p_action='renew' AND (p_password<>'' OR p_expires<1))
       OR (p_action='revoke' AND (p_password<>'' OR p_expires<>0)) THEN
        RAISE EXCEPTION 'invalid statement provider action payload';
    END IF;
    statement_hash:=encode(sha256(convert_to(p_statements,'UTF8')),'hex');
    payload_hash:=encode(sha256(convert_to(
       jsonb_build_array(p_fence,p_id,p_name,p_seq,p_action,p_expires,
                         p_password,p_digest,p_statements)::text,'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
      VALUES(session_user,p_fence,0) ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO l FROM heptabao_provider.statement_leases
      WHERE manager=session_user AND lease_id=p_id FOR UPDATE;
    existing:=FOUND;
    IF existing THEN
        IF l.fence_id<>p_fence OR l.username<>p_name OR p_seq<l.seq THEN
            RAISE EXCEPTION 'statement provider identity or fence mismatch';
        END IF;
        IF p_seq=l.seq THEN
            IF floor<p_seq OR l.request_digest<>p_digest
               OR l.statements_digest<>statement_hash OR l.payload_digest<>payload_hash
               OR l.action<>p_action OR l.expires<>p_expires THEN
                RAISE EXCEPTION 'statement provider semantic conflict';
            END IF;
            RETURN heptabao_provider.observe_statement(p_id);
        END IF;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale statement operation';
    END IF;
    IF NOT existing THEN
        SELECT count(*) INTO identity_count FROM heptabao_provider.statement_leases
          WHERE manager=session_user;
        IF p_action='issue' AND identity_count>=4096 THEN
            RAISE EXCEPTION 'statement provider issuance capacity exhausted';
        END IF;
        IF identity_count>=8192 THEN
            RAISE EXCEPTION 'statement provider cleanup capacity exhausted';
        END IF;
    END IF;
    IF existing AND l.action='revoke' AND p_action<>'revoke' THEN
        RAISE EXCEPTION 'statement provider resurrection rejected';
    END IF;
    IF p_action='issue' THEN
        IF existing OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=p_name) THEN
            RAISE EXCEPTION 'statement provider issue collision';
        END IF;
        IF p_expires<=extract(epoch FROM clock_timestamp())::bigint
           OR p_expires>extract(epoch FROM clock_timestamp())::bigint+86400 THEN
            RAISE EXCEPTION 'statement provider TTL outside bounds';
        END IF;
    ELSIF p_action='renew' THEN
        IF NOT existing OR l.action='revoke' OR p_expires<=l.expires THEN
            RAISE EXCEPTION 'statement provider renewal rejected';
        END IF;
        observed:=heptabao_provider.observe_statement(p_id);
        IF (observed->>'controlled')::boolean IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'statement provider role drift';
        END IF;
    END IF;
    expiration:=to_char(to_timestamp(GREATEST(p_expires,0)) AT TIME ZONE 'UTC',
                          'YYYY-MM-DD HH24:MI:SS') || '+0000';
    FOR statement IN SELECT jsonb_array_elements_text(parsed_statements) LOOP
        rendered:=replace(replace(replace(replace(statement,
           '{{name}}',p_name),'{{username}}',p_name),
           '{{password}}',p_password),'{{expiration}}',expiration);
        EXECUTE rendered;
    END LOOP;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,
           rolbypassrls,rolvaliduntil,rolpassword INTO r
      FROM pg_authid WHERE rolname=p_name;
    role_found:=FOUND;
    SELECT count(*) INTO sessions FROM pg_stat_activity WHERE usename=p_name;
    IF p_action IN ('issue','renew') THEN
        IF NOT role_found OR NOT r.rolcanlogin OR r.rolpassword IS NULL
           OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
           OR r.rolreplication OR r.rolbypassrls
           OR extract(epoch FROM r.rolvaliduntil)::bigint<>p_expires
           OR (p_action='renew' AND (r.oid<>l.role_oid
                OR encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex')<>l.password_digest)) THEN
            RAISE EXCEPTION 'statement provider postcondition failed';
        END IF;
    ELSIF role_found AND (r.rolcanlogin OR sessions<>0) THEN
        RAISE EXCEPTION 'statement provider revocation is not terminal';
    END IF;
    INSERT INTO heptabao_provider.statement_leases(
       manager,fence_id,lease_id,username,seq,action,expires,request_digest,
       statements_digest,password_digest,role_oid,payload_digest)
    VALUES(session_user,p_fence,p_id,p_name,p_seq,p_action,p_expires,p_digest,
       statement_hash,
       CASE WHEN role_found THEN encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex') END,
       CASE WHEN role_found THEN r.oid END,payload_hash)
    ON CONFLICT(manager,lease_id) DO UPDATE SET
       fence_id=EXCLUDED.fence_id,seq=EXCLUDED.seq,action=EXCLUDED.action,
       expires=EXCLUDED.expires,request_digest=EXCLUDED.request_digest,
       statements_digest=EXCLUDED.statements_digest,
       password_digest=EXCLUDED.password_digest,role_oid=EXCLUDED.role_oid,
       payload_digest=EXCLUDED.payload_digest;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.observe_statement(p_id);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.apply_statements(
    text,text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.retire_statement(
    p_fence text,p_id text,p_name text,p_seq bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE l heptabao_provider.statement_leases%ROWTYPE; floor bigint; observed jsonb;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$' OR p_id !~ '^hb1:[0-9a-f]{64}$'
       OR p_name !~ '^hbp_[0-9a-f]{32}$' OR p_seq<1 THEN
        RAISE EXCEPTION 'invalid statement retirement';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(session_user || ':' || p_fence,0));
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    IF COALESCE(floor,0)<p_seq THEN
        RAISE EXCEPTION 'statement retirement fence missing';
    END IF;
    SELECT * INTO l FROM heptabao_provider.statement_leases
      WHERE manager=session_user AND lease_id=p_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN heptabao_provider.statement_retired(p_fence,p_id,p_name,p_seq);
    END IF;
    IF l.fence_id<>p_fence OR l.username<>p_name OR l.seq<>p_seq
       OR l.action<>'revoke' THEN
        RAISE EXCEPTION 'statement retirement identity mismatch';
    END IF;
    observed:=heptabao_provider.observe_statement(p_id);
    IF (observed->>'terminal')::boolean IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'statement retirement is not terminal';
    END IF;
    DELETE FROM heptabao_provider.statement_leases
      WHERE manager=session_user AND lease_id=p_id;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.retire_statement(text,text,text,bigint) FROM PUBLIC;

COMMIT;

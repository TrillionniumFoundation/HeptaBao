-- Operator-installed PostgreSQL 17 provider contract. Execute as a dedicated
-- privileged schema owner; grant only the explicitly listed functions to the login manager.
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
       OR p_name !~ '^hbp_([0-9a-f]{28}|[0-9a-f]{32})$' OR p_seq < 1 THEN
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
       OR p_name !~ '^hbp_([0-9a-f]{28}|[0-9a-f]{32})$' OR p_seq<1
       OR p_action NOT IN ('issue','renew','revoke') OR p_expires<0
       OR (p_action <> 'revoke' AND p_name !~ '^hbp_[0-9a-f]{32}$')
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
       OR p_name !~ '^hbp_([0-9a-f]{28}|[0-9a-f]{32})$' OR p_seq<1 THEN
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

-- PostgreSQL static-role and manager-password rotation extension.
CREATE TABLE heptabao_provider.static_roles (
    manager name NOT NULL,
    fence_id text NOT NULL CHECK(fence_id ~ '^hbf1:[0-9a-f]{64}$'),
    static_id text NOT NULL CHECK(static_id ~ '^hbs1:[0-9a-f]{64}$'),
    username name NOT NULL,
    seq bigint NOT NULL CHECK(seq > 0),
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    password_digest text NOT NULL,
    role_oid oid NOT NULL,
    rotated_at bigint NOT NULL CHECK(rotated_at >= 0),
    payload_digest text NOT NULL,
    retired boolean NOT NULL DEFAULT false,
    PRIMARY KEY(manager, static_id),
    UNIQUE(manager, username)
);
CREATE TABLE heptabao_provider.allowed_static_roles (
    manager name NOT NULL,
    username name NOT NULL,
    PRIMARY KEY(manager, username)
);
CREATE TABLE heptabao_provider.root_rotations (
    manager name PRIMARY KEY,
    fence_id text NOT NULL CHECK(fence_id ~ '^hbf1:[0-9a-f]{64}$'),
    root_id text NOT NULL CHECK(root_id ~ '^hbr1:[0-9a-f]{64}$'),
    seq bigint NOT NULL CHECK(seq > 0),
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    password_digest text NOT NULL,
    payload_digest text NOT NULL
);
REVOKE ALL ON heptabao_provider.static_roles,
    heptabao_provider.allowed_static_roles,
    heptabao_provider.root_rotations FROM PUBLIC;

CREATE FUNCTION heptabao_provider.static_protocol() RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT 'heptabao-postgresql-static-v1'::text $$;
REVOKE ALL ON FUNCTION heptabao_provider.static_protocol() FROM PUBLIC;

CREATE FUNCTION heptabao_provider.observe_static(p_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE s heptabao_provider.static_roles%ROWTYPE; r record;
BEGIN
    SELECT * INTO s FROM heptabao_provider.static_roles
      WHERE manager=session_user AND static_id=p_id;
    IF NOT FOUND OR s.retired THEN
        RETURN jsonb_build_object('found',false);
    END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls,rolpassword
      INTO r FROM pg_authid WHERE rolname=s.username;
    RETURN jsonb_build_object(
        'found',true,'static_id',s.static_id,'username',s.username,
        'seq',s.seq,'request_digest',s.request_digest,
        'rotated_at',s.rotated_at,
        'login',COALESCE(r.rolcanlogin,false),
        'controlled',r.oid=s.role_oid AND r.rolpassword IS NOT NULL
            AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
                     OR r.rolreplication OR r.rolbypassrls)
            AND encode(sha256(convert_to(r.rolpassword,'UTF8')),'hex')
                =s.password_digest);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.observe_static(text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.rotate_static(
    p_fence text,p_id text,p_name text,p_seq bigint,
    p_password text,p_digest text,p_rotated_at bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE s heptabao_provider.static_roles%ROWTYPE; r record;
        floor bigint; payload_hash text; existing_record boolean;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_password IS NULL OR p_digest IS NULL OR p_rotated_at IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbs1:[0-9a-f]{64}$'
       OR p_name !~ '^[A-Za-z_][A-Za-z0-9_-]{0,62}$'
       OR p_seq<1 OR p_password !~ '^[0-9a-f]{64}$'
       OR p_digest !~ '^[0-9a-f]{64}$' OR p_rotated_at<0 THEN
        RAISE EXCEPTION 'invalid static-role rotation';
    END IF;
    IF p_name=session_user THEN
        RAISE EXCEPTION 'manager credential cannot be a static role';
    END IF;
    IF NOT EXISTS(
        SELECT 1 FROM heptabao_provider.allowed_static_roles
         WHERE manager=session_user AND username=p_name
    ) THEN
        RAISE EXCEPTION 'static-role target is not independently enrolled';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_name,p_seq,p_password,
                          p_digest,p_rotated_at)::text,'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(
        hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
        VALUES(session_user,p_fence,0)
        ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO s FROM heptabao_provider.static_roles
      WHERE manager=session_user AND static_id=p_id FOR UPDATE;
    existing_record:=FOUND;
    IF existing_record THEN
        IF s.fence_id<>p_fence OR s.username<>p_name OR p_seq<s.seq THEN
            RAISE EXCEPTION 'static-role identity or fence mismatch';
        END IF;
        IF p_seq=s.seq THEN
            IF floor<p_seq OR s.retired OR s.request_digest<>p_digest
               OR s.payload_digest<>payload_hash OR s.rotated_at<>p_rotated_at THEN
                RAISE EXCEPTION 'static-role semantic conflict';
            END IF;
            RETURN heptabao_provider.observe_static(p_id);
        END IF;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale static rotation';
    END IF;
    IF NOT existing_record AND (
        SELECT count(*) FROM heptabao_provider.static_roles
         WHERE manager=session_user
    )>=4096 THEN
        RAISE EXCEPTION 'static-role provider identity capacity exhausted';
    END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls INTO r
      FROM pg_authid WHERE rolname=p_name;
    IF NOT FOUND OR NOT r.rolcanlogin
       OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
       OR r.rolreplication OR r.rolbypassrls THEN
        RAISE EXCEPTION 'static-role target is absent or privileged';
    END IF;
    IF s.role_oid IS NOT NULL AND s.role_oid<>r.oid THEN
        RAISE EXCEPTION 'static-role target identity changed';
    END IF;
    EXECUTE format('ALTER ROLE %I PASSWORD %L',p_name,p_password);
    INSERT INTO heptabao_provider.static_roles(
        manager,fence_id,static_id,username,seq,request_digest,
        password_digest,role_oid,rotated_at,payload_digest,retired)
    VALUES(session_user,p_fence,p_id,p_name,p_seq,p_digest,
        (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
           FROM pg_authid WHERE rolname=p_name),
        r.oid,p_rotated_at,payload_hash,false)
    ON CONFLICT(manager,static_id) DO UPDATE SET
        fence_id=EXCLUDED.fence_id,username=EXCLUDED.username,
        seq=EXCLUDED.seq,request_digest=EXCLUDED.request_digest,
        password_digest=EXCLUDED.password_digest,
        role_oid=EXCLUDED.role_oid,rotated_at=EXCLUDED.rotated_at,
        payload_digest=EXCLUDED.payload_digest,retired=false;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.observe_static(p_id);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.rotate_static(
    text,text,text,bigint,text,text,bigint) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.static_retired(
    p_fence text,p_id text,p_name text,p_seq bigint,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE s heptabao_provider.static_roles%ROWTYPE; floor bigint;
        payload_hash text;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL
       OR p_seq IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbs1:[0-9a-f]{64}$'
       OR p_name !~ '^[A-Za-z_][A-Za-z0-9_-]{0,62}$'
       OR p_seq<1 OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid static-role retirement query';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array('retire-static',p_fence,p_id,p_name,p_seq,p_digest)::text,
        'UTF8')),'hex');
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence;
    SELECT * INTO s FROM heptabao_provider.static_roles
      WHERE manager=session_user AND static_id=p_id;
    IF NOT FOUND THEN RETURN false; END IF;
    RETURN COALESCE(floor,0)>=p_seq
       AND s.fence_id=p_fence AND s.username=p_name
       AND s.seq=p_seq AND s.request_digest=p_digest
       AND s.payload_digest=payload_hash AND s.retired;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.static_retired(
    text,text,text,bigint,text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.retire_static(
    p_fence text,p_id text,p_name text,p_seq bigint,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE s heptabao_provider.static_roles%ROWTYPE; floor bigint;
        payload_hash text;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL
       OR p_seq IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbs1:[0-9a-f]{64}$'
       OR p_name !~ '^[A-Za-z_][A-Za-z0-9_-]{0,62}$'
       OR p_seq<1 OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid static-role retirement';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array('retire-static',p_fence,p_id,p_name,p_seq,p_digest)::text,
        'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(
        hashtextextended(session_user || ':' || p_fence,0));
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'static-role retirement fence missing';
    END IF;
    SELECT * INTO s FROM heptabao_provider.static_roles
      WHERE manager=session_user AND static_id=p_id FOR UPDATE;
    IF NOT FOUND OR s.fence_id<>p_fence OR s.username<>p_name OR p_seq<s.seq THEN
        RAISE EXCEPTION 'static-role retirement identity or fence mismatch';
    END IF;
    IF p_seq=s.seq THEN
        IF floor<p_seq OR NOT s.retired OR s.request_digest<>p_digest
           OR s.payload_digest<>payload_hash THEN
            RAISE EXCEPTION 'static-role retirement semantic conflict';
        END IF;
        RETURN true;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale static retirement';
    END IF;
    UPDATE heptabao_provider.static_roles SET
        fence_id=p_fence,seq=p_seq,request_digest=p_digest,
        payload_digest=payload_hash,retired=true
      WHERE manager=session_user AND static_id=p_id;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.static_retired(
        p_fence,p_id,p_name,p_seq,p_digest);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.retire_static(
    text,text,text,bigint,text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.root_rotation_retriable(
    p_fence text,p_id text,p_seq bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE r heptabao_provider.root_rotations%ROWTYPE; verifier text;
        floor bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_seq IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbr1:[0-9a-f]{64}$' OR p_seq<1 THEN
        RAISE EXCEPTION 'invalid root-rotation retry query';
    END IF;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence;
    IF COALESCE(floor,0)<=p_seq THEN RETURN false; END IF;
    SELECT * INTO r FROM heptabao_provider.root_rotations
      WHERE manager=session_user;
    IF NOT FOUND THEN RETURN true; END IF;
    SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
      INTO verifier FROM pg_authid WHERE rolname=session_user;
    RETURN r.fence_id=p_fence AND r.root_id=p_id AND r.seq<p_seq
       AND r.password_digest=verifier;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.root_rotation_retriable(
    text,text,bigint) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.root_rotation_observed(
    p_fence text,p_id text,p_seq bigint,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE r heptabao_provider.root_rotations%ROWTYPE; verifier text;
        floor bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_seq IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbr1:[0-9a-f]{64}$' OR p_seq<1
       OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid root-rotation query';
    END IF;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence;
    SELECT * INTO r FROM heptabao_provider.root_rotations
      WHERE manager=session_user;
    IF NOT FOUND OR COALESCE(floor,0)<p_seq
       OR r.fence_id<>p_fence OR r.root_id<>p_id
       OR r.seq<>p_seq OR r.request_digest<>p_digest THEN
        RETURN false;
    END IF;
    SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
      INTO verifier FROM pg_authid WHERE rolname=session_user;
    RETURN verifier=r.password_digest;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.root_rotation_observed(
    text,text,bigint,text) FROM PUBLIC;

CREATE FUNCTION heptabao_provider.rotate_root(
    p_fence text,p_id text,p_seq bigint,p_password text,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE existing heptabao_provider.root_rotations%ROWTYPE;
        manager_role record; floor bigint; payload_hash text;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_seq IS NULL
       OR p_password IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbr1:[0-9a-f]{64}$' OR p_seq<1
       OR p_password !~ '^[0-9a-f]{64}$'
       OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid root rotation';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_seq,p_password,p_digest)::text,
        'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(
        hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
        VALUES(session_user,p_fence,0)
        ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO existing FROM heptabao_provider.root_rotations
      WHERE manager=session_user FOR UPDATE;
    IF FOUND THEN
        IF existing.fence_id<>p_fence OR existing.root_id<>p_id
           OR p_seq<existing.seq THEN
            RAISE EXCEPTION 'root-rotation identity or fence mismatch';
        END IF;
        IF p_seq=existing.seq THEN
            IF floor<p_seq OR existing.request_digest<>p_digest
               OR existing.payload_digest<>payload_hash THEN
                RAISE EXCEPTION 'root-rotation semantic conflict';
            END IF;
            RETURN heptabao_provider.root_rotation_observed(
                p_fence,p_id,p_seq,p_digest);
        END IF;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale root rotation';
    END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls INTO manager_role
      FROM pg_authid WHERE rolname=session_user;
    IF NOT FOUND OR NOT manager_role.rolcanlogin
       OR manager_role.rolsuper OR manager_role.rolcreatedb
       OR manager_role.rolcreaterole OR manager_role.rolreplication
       OR manager_role.rolbypassrls THEN
        RAISE EXCEPTION 'database manager role is absent or privileged';
    END IF;
    EXECUTE format('ALTER ROLE %I PASSWORD %L',session_user,p_password);
    INSERT INTO heptabao_provider.root_rotations(
        manager,fence_id,root_id,seq,request_digest,
        password_digest,payload_digest)
    VALUES(session_user,p_fence,p_id,p_seq,p_digest,
        (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
           FROM pg_authid WHERE rolname=session_user),payload_hash)
    ON CONFLICT(manager) DO UPDATE SET
        fence_id=EXCLUDED.fence_id,root_id=EXCLUDED.root_id,
        seq=EXCLUDED.seq,request_digest=EXCLUDED.request_digest,
        password_digest=EXCLUDED.password_digest,
        payload_digest=EXCLUDED.payload_digest;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.root_rotation_observed(
        p_fence,p_id,p_seq,p_digest);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.rotate_root(
    text,text,bigint,text,text) FROM PUBLIC;

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

-- PostgreSQL password-authentication extension.
-- Client passwords remain only in the encrypted HeptaBao intent/response path.
-- SCRAM mode sends a canonical verifier to PostgreSQL; the provider entry
-- rejects raw or noncanonical material before the existing owner/fence ledger.
CREATE OR REPLACE FUNCTION heptabao_provider.valid_scram_verifier(p_value text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
DECLARE parts text[];
BEGIN
    parts:=regexp_match(p_value,
        '^SCRAM-SHA-256[$]4096:([A-Za-z0-9+/]{22}==)[$]([A-Za-z0-9+/]{43}=):([A-Za-z0-9+/]{43}=)$');
    IF parts IS NULL THEN RETURN false; END IF;
    RETURN encode(decode(parts[1],'base64'),'base64')=parts[1]
       AND encode(decode(parts[2],'base64'),'base64')=parts[2]
       AND encode(decode(parts[3],'base64'),'base64')=parts[3]
       AND octet_length(decode(parts[1],'base64'))=16
       AND octet_length(decode(parts[2],'base64'))=32
       AND octet_length(decode(parts[3],'base64'))=32;
EXCEPTION WHEN others THEN
    RETURN false;
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.valid_scram_verifier(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.valid_password_credential(p_value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog
AS $$ SELECT p_value ~ '^[0-9a-f]{64}$'
          OR heptabao_provider.valid_scram_verifier(p_value) $$;
REVOKE ALL ON FUNCTION heptabao_provider.valid_password_credential(text) FROM PUBLIC;
CREATE OR REPLACE FUNCTION heptabao_provider.apply(
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
       OR p_name !~ '^hbp_([0-9a-f]{28}|[0-9a-f]{32})$' OR p_seq<1
       OR p_action NOT IN ('issue','renew','revoke') OR p_expires<0
       OR (p_action <> 'revoke' AND p_name !~ '^hbp_[0-9a-f]{32}$')
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
        IF existing OR NOT heptabao_provider.valid_password_credential(p_password) THEN RAISE EXCEPTION 'provider issue rejected'; END IF;
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

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_static(
    p_fence text,p_id text,p_name text,p_seq bigint,
    p_password text,p_digest text,p_rotated_at bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE s heptabao_provider.static_roles%ROWTYPE; r record;
        floor bigint; payload_hash text; existing_record boolean;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_name IS NULL OR p_seq IS NULL
       OR p_password IS NULL OR p_digest IS NULL OR p_rotated_at IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbs1:[0-9a-f]{64}$'
       OR p_name !~ '^[A-Za-z_][A-Za-z0-9_-]{0,62}$'
       OR p_seq<1 OR NOT heptabao_provider.valid_password_credential(p_password)
       OR p_digest !~ '^[0-9a-f]{64}$' OR p_rotated_at<0 THEN
        RAISE EXCEPTION 'invalid static-role rotation';
    END IF;
    IF p_name=session_user THEN
        RAISE EXCEPTION 'manager credential cannot be a static role';
    END IF;
    IF NOT EXISTS(
        SELECT 1 FROM heptabao_provider.allowed_static_roles
         WHERE manager=session_user AND username=p_name
    ) THEN
        RAISE EXCEPTION 'static-role target is not independently enrolled';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_name,p_seq,p_password,
                          p_digest,p_rotated_at)::text,'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(
        hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
        VALUES(session_user,p_fence,0)
        ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO s FROM heptabao_provider.static_roles
      WHERE manager=session_user AND static_id=p_id FOR UPDATE;
    existing_record:=FOUND;
    IF existing_record THEN
        IF s.fence_id<>p_fence OR s.username<>p_name OR p_seq<s.seq THEN
            RAISE EXCEPTION 'static-role identity or fence mismatch';
        END IF;
        IF p_seq=s.seq THEN
            IF floor<p_seq OR s.retired OR s.request_digest<>p_digest
               OR s.payload_digest<>payload_hash OR s.rotated_at<>p_rotated_at THEN
                RAISE EXCEPTION 'static-role semantic conflict';
            END IF;
            RETURN heptabao_provider.observe_static(p_id);
        END IF;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale static rotation';
    END IF;
    IF NOT existing_record AND (
        SELECT count(*) FROM heptabao_provider.static_roles
         WHERE manager=session_user
    )>=4096 THEN
        RAISE EXCEPTION 'static-role provider identity capacity exhausted';
    END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls INTO r
      FROM pg_authid WHERE rolname=p_name;
    IF NOT FOUND OR NOT r.rolcanlogin
       OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
       OR r.rolreplication OR r.rolbypassrls THEN
        RAISE EXCEPTION 'static-role target is absent or privileged';
    END IF;
    IF s.role_oid IS NOT NULL AND s.role_oid<>r.oid THEN
        RAISE EXCEPTION 'static-role target identity changed';
    END IF;
    EXECUTE format('ALTER ROLE %I PASSWORD %L',p_name,p_password);
    INSERT INTO heptabao_provider.static_roles(
        manager,fence_id,static_id,username,seq,request_digest,
        password_digest,role_oid,rotated_at,payload_digest,retired)
    VALUES(session_user,p_fence,p_id,p_name,p_seq,p_digest,
        (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
           FROM pg_authid WHERE rolname=p_name),
        r.oid,p_rotated_at,payload_hash,false)
    ON CONFLICT(manager,static_id) DO UPDATE SET
        fence_id=EXCLUDED.fence_id,username=EXCLUDED.username,
        seq=EXCLUDED.seq,request_digest=EXCLUDED.request_digest,
        password_digest=EXCLUDED.password_digest,
        role_oid=EXCLUDED.role_oid,rotated_at=EXCLUDED.rotated_at,
        payload_digest=EXCLUDED.payload_digest,retired=false;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.observe_static(p_id);
END $$;

REVOKE ALL ON FUNCTION heptabao_provider.rotate_static(text,text,text,bigint,text,text,bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_root(
    p_fence text,p_id text,p_seq bigint,p_password text,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE existing heptabao_provider.root_rotations%ROWTYPE;
        manager_role record; floor bigint; payload_hash text;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_seq IS NULL
       OR p_password IS NULL OR p_digest IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbr1:[0-9a-f]{64}$' OR p_seq<1
       OR NOT heptabao_provider.valid_password_credential(p_password)
       OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid root rotation';
    END IF;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_seq,p_password,p_digest)::text,
        'UTF8')),'hex');
    PERFORM pg_advisory_xact_lock(
        hashtextextended(session_user || ':' || p_fence,0));
    INSERT INTO heptabao_provider.fences(manager,fence_id,last_seq)
        VALUES(session_user,p_fence,0)
        ON CONFLICT(manager,fence_id) DO NOTHING;
    SELECT last_seq INTO floor FROM heptabao_provider.fences
      WHERE manager=session_user AND fence_id=p_fence FOR UPDATE;
    SELECT * INTO existing FROM heptabao_provider.root_rotations
      WHERE manager=session_user FOR UPDATE;
    IF FOUND THEN
        IF existing.fence_id<>p_fence OR existing.root_id<>p_id
           OR p_seq<existing.seq THEN
            RAISE EXCEPTION 'root-rotation identity or fence mismatch';
        END IF;
        IF p_seq=existing.seq THEN
            IF floor<p_seq OR existing.request_digest<>p_digest
               OR existing.payload_digest<>payload_hash THEN
                RAISE EXCEPTION 'root-rotation semantic conflict';
            END IF;
            RETURN heptabao_provider.root_rotation_observed(
                p_fence,p_id,p_seq,p_digest);
        END IF;
    END IF;
    IF p_seq<=floor THEN
        RAISE EXCEPTION 'provider global fence rejected stale root rotation';
    END IF;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls INTO manager_role
      FROM pg_authid WHERE rolname=session_user;
    IF NOT FOUND OR NOT manager_role.rolcanlogin
       OR manager_role.rolsuper OR manager_role.rolcreatedb
       OR manager_role.rolcreaterole OR manager_role.rolreplication
       OR manager_role.rolbypassrls THEN
        RAISE EXCEPTION 'database manager role is absent or privileged';
    END IF;
    EXECUTE format('ALTER ROLE %I PASSWORD %L',session_user,p_password);
    INSERT INTO heptabao_provider.root_rotations(
        manager,fence_id,root_id,seq,request_digest,
        password_digest,payload_digest)
    VALUES(session_user,p_fence,p_id,p_seq,p_digest,
        (SELECT encode(sha256(convert_to(rolpassword,'UTF8')),'hex')
           FROM pg_authid WHERE rolname=session_user),payload_hash)
    ON CONFLICT(manager) DO UPDATE SET
        fence_id=EXCLUDED.fence_id,root_id=EXCLUDED.root_id,
        seq=EXCLUDED.seq,request_digest=EXCLUDED.request_digest,
        password_digest=EXCLUDED.password_digest,
        payload_digest=EXCLUDED.payload_digest;
    UPDATE heptabao_provider.fences SET last_seq=p_seq
      WHERE manager=session_user AND fence_id=p_fence;
    RETURN heptabao_provider.root_rotation_observed(
        p_fence,p_id,p_seq,p_digest);
END $$;

REVOKE ALL ON FUNCTION heptabao_provider.rotate_root(text,text,bigint,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.apply_statements(
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
    IF (p_action='issue' AND (NOT heptabao_provider.valid_password_credential(p_password) OR p_expires<1))
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

REVOKE ALL ON FUNCTION heptabao_provider.apply_statements(text,text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.password_authentication_protocol() RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT 'heptabao-postgresql-password-authentication-v1'::text $$;
REVOKE ALL ON FUNCTION heptabao_provider.password_authentication_protocol() FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.apply_scram(
    p_fence text,p_id text,p_name text,p_seq bigint,p_action text,p_expires bigint,
    p_group text,p_password text,p_digest text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (p_action='issue' AND NOT COALESCE(
            heptabao_provider.valid_scram_verifier(p_password),false))
       OR (p_action<>'issue' AND p_password IS DISTINCT FROM '') THEN
        RAISE EXCEPTION 'invalid SCRAM provider credential';
    END IF;
    RETURN heptabao_provider.apply(
        p_fence,p_id,p_name,p_seq,p_action,p_expires,p_group,p_password,p_digest);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.apply_scram(
    text,text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_static_scram(
    p_fence text,p_id text,p_name text,p_seq bigint,
    p_password text,p_digest text,p_rotated_at bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT COALESCE(heptabao_provider.valid_scram_verifier(p_password),false) THEN
        RAISE EXCEPTION 'invalid SCRAM static-role credential';
    END IF;
    RETURN heptabao_provider.rotate_static(
        p_fence,p_id,p_name,p_seq,p_password,p_digest,p_rotated_at);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.rotate_static_scram(
    text,text,text,bigint,text,text,bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_root_scram(
    p_fence text,p_id text,p_seq bigint,p_password text,p_digest text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT COALESCE(heptabao_provider.valid_scram_verifier(p_password),false) THEN
        RAISE EXCEPTION 'invalid SCRAM root credential';
    END IF;
    RETURN heptabao_provider.rotate_root(p_fence,p_id,p_seq,p_password,p_digest);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.rotate_root_scram(
    text,text,bigint,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.apply_statements_scram(
    p_fence text,p_id text,p_name text,p_seq bigint,p_action text,p_expires bigint,
    p_password text,p_digest text,p_statements text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (p_action='issue' AND NOT COALESCE(
            heptabao_provider.valid_scram_verifier(p_password),false))
       OR (p_action<>'issue' AND p_password IS DISTINCT FROM '') THEN
        RAISE EXCEPTION 'invalid SCRAM statement credential';
    END IF;
    RETURN heptabao_provider.apply_statements(
        p_fence,p_id,p_name,p_seq,p_action,p_expires,
        p_password,p_digest,p_statements);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.apply_statements_scram(
    text,text,text,bigint,text,bigint,text,text,text) FROM PUBLIC;

COMMIT;
-- Explicit example, after CREATE ROLE hb_manager LOGIN PASSWORD ...:
-- GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.observe(text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retired(text,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply(text,text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retire(text,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.static_protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.observe_static(text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_static(text,text,text,bigint,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.static_retired(text,text,text,bigint,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retire_static(text,text,text,bigint,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.root_rotation_retriable(text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.root_rotation_observed(text,text,bigint,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root(text,text,bigint,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.statement_protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.observe_statement(text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.statement_retired(text,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply_statements(text,text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.retire_statement(text,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.password_authentication_protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply_scram(text,text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_static_scram(text,text,text,bigint,text,text,bigint) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root_scram(text,text,bigint,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.apply_statements_scram(text,text,text,bigint,text,bigint,text,text,text) TO hb_manager;
-- INSERT INTO heptabao_provider.allowed_static_roles VALUES ('hb_manager','app_static');
-- INSERT INTO heptabao_provider.allowed_groups VALUES ('hb_manager','app_reader');

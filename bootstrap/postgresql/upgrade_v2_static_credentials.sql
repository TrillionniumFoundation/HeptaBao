-- Owner-only forward extension for an installed PostgreSQL provider v2.
-- Execute with psql -X -v ON_ERROR_STOP=1. The API manager must not own this schema.
BEGIN;
DO $guard$
BEGIN
    IF heptabao_provider.protocol() IS DISTINCT FROM 'heptabao-postgresql-provider-v2' THEN
        RAISE EXCEPTION 'unsupported PostgreSQL provider protocol';
    END IF;
END
$guard$;
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

COMMIT;
-- The schema owner must explicitly grant only the eight new functions and
-- enroll every approved static username for each manager after review.

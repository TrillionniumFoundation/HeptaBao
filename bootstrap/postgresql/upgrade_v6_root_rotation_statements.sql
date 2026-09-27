-- Forward-only upgrade from the exact v5 generation provider contract.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
DO $$
BEGIN
    IF heptabao_provider.protocol() <> 'heptabao-postgresql-provider-v2'
       OR heptabao_provider.static_protocol() <> 'heptabao-postgresql-static-v1'
       OR heptabao_provider.statement_protocol() <> 'heptabao-postgresql-statements-v1'
       OR heptabao_provider.password_authentication_protocol()
            <> 'heptabao-postgresql-password-authentication-v1'
       OR heptabao_provider.generation_protocol()
            <> 'heptabao-postgresql-generation-v1' THEN
        RAISE EXCEPTION 'unexpected PostgreSQL provider protocol';
    END IF;
END $$;

-- PostgreSQL bounded root-rotation statement extension. The API retains the
-- official list/order/digest contract, but only admits ALTER ROLE/USER password
-- changes targeting the authenticated manager. Arbitrary SQL is deliberately
-- not executed through this SECURITY DEFINER boundary.
CREATE OR REPLACE FUNCTION heptabao_provider.root_statement_protocol() RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT 'heptabao-postgresql-root-statements-v1'::text $$;
REVOKE ALL ON FUNCTION heptabao_provider.root_statement_protocol() FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_root_statements(
    p_fence text,p_id text,p_seq bigint,p_password text,p_digest text,p_statements text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE existing heptabao_provider.root_rotations%ROWTYPE;
        manager_before record; manager_after record; floor bigint;
        payload_hash text; parsed_statements jsonb; statement text;
        normalized text; rendered text; total_bytes bigint;
BEGIN
    IF p_fence IS NULL OR p_id IS NULL OR p_seq IS NULL
       OR p_password IS NULL OR p_digest IS NULL OR p_statements IS NULL
       OR p_fence !~ '^hbf1:[0-9a-f]{64}$'
       OR p_id !~ '^hbr1:[0-9a-f]{64}$' OR p_seq<1
       OR NOT heptabao_provider.valid_password_credential(p_password)
       OR p_digest !~ '^[0-9a-f]{64}$' OR octet_length(p_statements)>69632 THEN
        RAISE EXCEPTION 'invalid root statement rotation';
    END IF;
    BEGIN
        parsed_statements:=p_statements::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'invalid root statement rotation';
    END;
    IF jsonb_typeof(parsed_statements)<>'array'
       OR jsonb_array_length(parsed_statements)<1
       OR jsonb_array_length(parsed_statements)>64
       OR EXISTS(SELECT 1 FROM jsonb_array_elements(parsed_statements) value
                   WHERE jsonb_typeof(value)<>'string') THEN
        RAISE EXCEPTION 'invalid root statement rotation';
    END IF;
    SELECT COALESCE(sum(octet_length(value)),0) INTO total_bytes
      FROM jsonb_array_elements_text(parsed_statements) value;
    IF total_bytes>65536 OR EXISTS(
       SELECT 1 FROM jsonb_array_elements_text(parsed_statements) value
        WHERE value='' OR octet_length(value)>16384) THEN
        RAISE EXCEPTION 'root rotation statement payload outside bounds';
    END IF;
    FOR statement IN SELECT jsonb_array_elements_text(parsed_statements) LOOP
        normalized:=regexp_replace(btrim(statement),'[[:space:]]+',' ','g');
        IF normalized <> ALL (ARRAY[
            'ALTER ROLE "{{username}}" PASSWORD ''{{password}}''',
            'ALTER ROLE "{{username}}" ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER ROLE "{{username}}" WITH PASSWORD ''{{password}}''',
            'ALTER ROLE "{{username}}" WITH ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER ROLE "{{name}}" PASSWORD ''{{password}}''',
            'ALTER ROLE "{{name}}" ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER ROLE "{{name}}" WITH PASSWORD ''{{password}}''',
            'ALTER ROLE "{{name}}" WITH ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER USER "{{username}}" PASSWORD ''{{password}}''',
            'ALTER USER "{{username}}" ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER USER "{{username}}" WITH PASSWORD ''{{password}}''',
            'ALTER USER "{{username}}" WITH ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER USER "{{name}}" PASSWORD ''{{password}}''',
            'ALTER USER "{{name}}" ENCRYPTED PASSWORD ''{{password}}''',
            'ALTER USER "{{name}}" WITH PASSWORD ''{{password}}''',
            'ALTER USER "{{name}}" WITH ENCRYPTED PASSWORD ''{{password}}'''
        ]::text[]) THEN
            RAISE EXCEPTION 'root rotation statement is outside bounded password-change grammar';
        END IF;
    END LOOP;
    payload_hash:=encode(sha256(convert_to(
        jsonb_build_array(p_fence,p_id,p_seq,p_password,p_digest,p_statements)::text,
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
           rolreplication,rolbypassrls INTO manager_before
      FROM pg_authid WHERE rolname=session_user;
    IF NOT FOUND OR NOT manager_before.rolcanlogin
       OR manager_before.rolsuper OR manager_before.rolcreatedb
       OR manager_before.rolcreaterole OR manager_before.rolreplication
       OR manager_before.rolbypassrls THEN
        RAISE EXCEPTION 'database manager role is absent or privileged';
    END IF;
    FOR statement IN SELECT jsonb_array_elements_text(parsed_statements) LOOP
        normalized:=regexp_replace(btrim(statement),'[[:space:]]+',' ','g');
        rendered:=replace(replace(normalized,
            '"{{name}}"',quote_ident(session_user)),
            '"{{username}}"',quote_ident(session_user));
        rendered:=replace(rendered,
            chr(39)||'{{password}}'||chr(39),quote_literal(p_password));
        EXECUTE rendered;
    END LOOP;
    SELECT oid,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,
           rolreplication,rolbypassrls,rolpassword INTO manager_after
      FROM pg_authid WHERE rolname=session_user;
    IF NOT FOUND OR manager_after.oid<>manager_before.oid
       OR NOT manager_after.rolcanlogin OR manager_after.rolpassword IS NULL
       OR manager_after.rolsuper OR manager_after.rolcreatedb
       OR manager_after.rolcreaterole OR manager_after.rolreplication
       OR manager_after.rolbypassrls THEN
        RAISE EXCEPTION 'root rotation statement postcondition failed';
    END IF;
    INSERT INTO heptabao_provider.root_rotations(
        manager,fence_id,root_id,seq,request_digest,
        password_digest,payload_digest)
    VALUES(session_user,p_fence,p_id,p_seq,p_digest,
        encode(sha256(convert_to(manager_after.rolpassword,'UTF8')),'hex'),
        payload_hash)
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
REVOKE ALL ON FUNCTION heptabao_provider.rotate_root_statements(
    text,text,bigint,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION heptabao_provider.rotate_root_statements_scram(
    p_fence text,p_id text,p_seq bigint,p_password text,p_digest text,p_statements text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT COALESCE(heptabao_provider.valid_scram_verifier(p_password),false) THEN
        RAISE EXCEPTION 'invalid SCRAM root statement credential';
    END IF;
    RETURN heptabao_provider.rotate_root_statements(
        p_fence,p_id,p_seq,p_password,p_digest,p_statements);
END $$;
REVOKE ALL ON FUNCTION heptabao_provider.rotate_root_statements_scram(
    text,text,bigint,text,text,text) FROM PUBLIC;

COMMIT;
-- Existing enrolled managers need these grants after upgrade:
-- GRANT EXECUTE ON FUNCTION heptabao_provider.root_statement_protocol() TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root_statements(text,text,bigint,text,text,text) TO hb_manager;
-- GRANT EXECUTE ON FUNCTION heptabao_provider.rotate_root_statements_scram(text,text,bigint,text,text,text) TO hb_manager;

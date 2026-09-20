#!/usr/bin/env python3
"""Real candidate + local HTTPS JWKS/discovery, rotation and restart tests.

No external issuer or credentials. This is not browser OIDC authorization-code
flow, complete JWT/OIDC equivalence, independent or production qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from external_tls_fixtures import JsonIssuer, b64

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


def signing_key(algorithm, kid):
    if algorithm == "RS256":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        p = private.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": b64(p.n.to_bytes(256,"big")), "e": b64(p.e.to_bytes(3,"big"))}
    elif algorithm == "ES256":
        private = ec.generate_private_key(ec.SECP256R1())
        p = private.public_key().public_numbers()
        jwk = {"kty":"EC", "crv":"P-256", "x":b64(p.x.to_bytes(32,"big")),"y":b64(p.y.to_bytes(32,"big"))}
    else:
        private = ed25519.Ed25519PrivateKey.generate()
        jwk = {"kty":"OKP", "crv":"Ed25519", "x":b64(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))}
    jwk.update({"kid": kid, "alg": algorithm, "use": "sig"})
    return private, jwk


def token(private, jwk, issuer, **extra):
    now = int(time.time())
    claims = {"iss":issuer,"aud":"heptabao-test","sub":"synthetic-subject", "iat":now, "exp":now+300,"jti":secrets.token_hex(16)}
    claims.update(extra)
    message=(b64(json.dumps({"alg":jwk["alg"],"kid":jwk["kid"],"typ":"JWT"}).encode())+"."+b64(json.dumps(claims).encode())).encode()
    if jwk["alg"]=="RS256": signature=private.sign(message,padding.PKCS1v15(),hashes.SHA256())
    elif jwk["alg"]=="ES256":
        a,b=decode_dss_signature(private.sign(message,ec.ECDSA(hashes.SHA256())));signature=a.to_bytes(32,"big")+b.to_bytes(32,"big")
    else: signature=private.sign(message)
    return message.decode()+"."+b64(signature)


def run(binary, root, checks):
    instance=Instance(binary, root / "candidate")
    issuer=JsonIssuer(instance.root/"tls.crt", instance.root/"tls.key")
    def check(name, condition):
        checks.append({"case":name,"passed":condition is True})
        if condition is not True: raise RuntimeError(name)
    config_path=instance.root/"server.json"
    config=json.loads(config_path.read_text());config["outbound_endpoints"]=[]
    config_path.write_text(json.dumps(config));config_path.chmod(0o600)
    private,jwk=signing_key("RS256","key-a")
    issuer.documents["/keys"]={"keys":[jwk]}
    issuer.documents["/.well-known/openid-configuration"]={"issuer":issuer.origin,"jwks_uri":issuer.origin+"/keys"}
    try:
        instance.start()
        status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1});check("initialize",status==200)
        key=init["keys_base64"][0];instance.token=init["root_token"]
        check("unseal",instance.call("POST","sys/unseal",{"key":key})[0]==200)
        check("mount",instance.call("POST","sys/auth/federated",{"type":"jwt"})[0]==204)
        params={"bound_issuer":issuer.origin,"oidc_discovery_url":issuer.origin,"oidc_discovery_ca_pem":(instance.root/"ca.crt").read_text(),"jwt_supported_algs":["RS256","ES256","EdDSA"]}
        check("discovery_configuration",instance.call("POST","auth/federated/config",params)[0]==204)
        check("configuration_fetches_discovery_without_jwks",issuer.calls==["/.well-known/openid-configuration"])
        check("role",instance.call("POST","auth/federated/role/test",{"role_type":"jwt","user_claim":"sub","bound_audiences":["heptabao-test"],"token_policies":["default"]})[0]==204)
        def login(value): return instance.call("POST","auth/federated/login",{"role":"test","jwt":value},token="")
        jwt=token(private,jwk,issuer.origin)
        status,logged=login(jwt);check("real_rsa_signature_login",status==200 and bool(logged.get("auth",{}).get("entity_id")))
        entity=logged["auth"]["entity_id"];old_access=logged["auth"]["client_token"]
        status,repeated=login(jwt)
        check("same_assertion_issues_distinct_service_token",status==200
              and repeated.get("auth",{}).get("entity_id")==entity
              and bool(repeated.get("auth",{}).get("client_token"))
              and repeated["auth"]["client_token"]!=old_access)
        check("wrong_audience_rejected",login(token(private,jwk,issuer.origin,aud="other"))[0]==400)
        check("wrong_issuer_rejected",login(token(private,jwk,"https://wrong.invalid:443"))[0]==400)
        new_private,new_jwk=signing_key("ES256","key-b");issuer.documents["/keys"]={"keys":[new_jwk]}
        check("removed_key_immediately_rejected",login(token(private,jwk,issuer.origin))[0]==400)
        status,logged=login(token(new_private,new_jwk,issuer.origin));check("p256_rotation_login",status==200)
        check("rotation_preserves_subject_identity",logged["auth"]["entity_id"]==entity)
        for mode in ["redirect","duplicate","oversized","unavailable"]:
            issuer.mode=mode
            check(mode+"_no_stale_fallback",login(token(new_private,new_jwk,issuer.origin))[0]>=400)
        issuer.mode="normal"
        issuer.documents["/.well-known/openid-configuration"]["issuer"]="https://wrong.invalid:443"
        check("discovery_issuer_mismatch",login(token(new_private,new_jwk,issuer.origin))[0]>=400)
        issuer.documents["/.well-known/openid-configuration"]["issuer"]=issuer.origin
        issuer.documents["/.well-known/openid-configuration"]["jwks_uri"]="https://untrusted.invalid:443/keys"
        check("cross_origin_metadata_rejected",login(token(new_private,new_jwk,issuer.origin))[0]>=400)
        issuer.documents["/.well-known/openid-configuration"]["jwks_uri"]=issuer.origin+"/keys"
        check("entity_disable",instance.call("POST","identity/entity/id/"+entity,{"disabled":True})[0]==204)
        check("disabled_subject_login_rejected",login(token(new_private,new_jwk,issuer.origin))[0]==403)
        check("existing_subject_token_rejected",instance.call("GET","auth/token/lookup-self",token=old_access)[0]==403)
        check("reenable_subject",instance.call("POST","identity/entity/id/"+entity,{"disabled":False})[0]==204)
        check("key_source_exclusive",instance.call("POST","auth/federated/config",dict(params,jwks_url=issuer.origin+"/keys"))[0]==400)
        private,jwk=signing_key("EdDSA","key-c");issuer.documents["/keys"]={"keys":[jwk]}
        check("eddsa_rotation_login",login(token(private,jwk,issuer.origin))[0]==200)
        instance.stop();instance.start();check("restart_unseal",instance.call("POST","sys/unseal",{"key":key})[0]==200)
        check("restart_does_not_resurrect_old_key",login(token(new_private,new_jwk,issuer.origin))[0]==400)
        jwt=token(private,jwk,issuer.origin);status,logged=login(jwt)
        check("restart_current_key_login",status==200)
        preceding_access=logged["auth"]["client_token"]
        instance.stop();instance.start();check("second_restart_unseal",instance.call("POST","sys/unseal",{"key":key})[0]==200)
        status,repeated=login(jwt)
        check("same_assertion_reusable_after_restart",status==200
              and repeated.get("auth",{}).get("entity_id")==entity
              and bool(repeated.get("auth",{}).get("client_token"))
              and repeated["auth"]["client_token"]!=preceding_access)
        check("not_browser_oidc",instance.call("POST","auth/federated/role/oidc",{"role_type":"oidc","user_claim":"sub","bound_audiences":["heptabao-test"]})[0]==501)
        params={"bound_issuer":issuer.origin,"jwks_url":issuer.origin+"/keys","jwks_ca_pem":(instance.root/"ca.crt").read_text(),"jwt_supported_algs":["EdDSA"]}
        check("direct_jwks_configuration",instance.call("POST","auth/federated/config",params)[0]==204)
        check("direct_jwks_login",login(token(private,jwk,issuer.origin))[0]==200)
        params["jwks_url"]="https://unenrolled.invalid:443/keys"
        check("unresolvable_configuration_not_activated",instance.call("POST","auth/federated/config",params)[0]==400)
        check("rejected_configuration_preserves_predecessor",login(token(private,jwk,issuer.origin))[0]==200)
        # A malformed CA binding fails before any auth/secret use on restart.
        instance.stop();config["outbound_endpoints"]=[{"origin":issuer.origin,"address":f"127.0.0.1:{issuer.port}","server_name":"mismatch.invalid","ca_pem":(instance.root/"ca.crt").read_text()}]
        config_path.write_text(json.dumps(config))
        try: instance.start()
        except RuntimeError: check("invalid_host_enrollment_rejected",True)
        else: check("invalid_host_enrollment_rejected",False)
    finally:
        instance.stop();issuer.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--binary",required=True,type=Path);parser.add_argument("--output",required=True,type=Path);args=parser.parse_args()
    binary=args.binary.resolve(strict=True);root=Path(tempfile.mkdtemp(prefix="heptabao-jwks-"));root.chmod(0o700)
    report={"schema":"heptabao.remote-jwks-live.v1","checks":[],"independent_attestation":False,"full_oidc_compatibility":False,"candidate_binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest()}
    try:run(binary,root,report["checks"]);report["status"]="passed"
    except Exception as error:report["status"]="failed";report["safe_error"]=str(error) if isinstance(error,RuntimeError) else type(error).__name__
    finally:shutil.rmtree(root)
    report["check_count"]=len(report["checks"]);report["binary_unchanged"]=hashlib.sha256(binary.read_bytes()).hexdigest()==report["candidate_binary_sha256"]
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as output:json.dump(report,output,indent=2)
    print(json.dumps({k:report[k] for k in ("status","check_count","binary_unchanged")}|{"failure":report.get("safe_error")}))
    return 0 if report["status"]=="passed" and report["binary_unchanged"] else 1
if __name__=="__main__":raise SystemExit(main())

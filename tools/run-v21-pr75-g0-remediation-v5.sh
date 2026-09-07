#!/usr/bin/env bash
set -euo pipefail

readonly source_sha='ff8ff379509baa95f54744f0b931810d1f115211'
readonly target_branch='codex/v2.1-main-convergence-durable-runtime-20260907'
readonly overlay_sha256='02f72fd1488f82687a548fbd9da5337f7b8f48affb65baeb92f58f58ff2e1b30'

[[ "$GITHUB_REPOSITORY" == 'TrillionniumFoundation/HeptaBao' ]]
[[ "$GITHUB_REF" == 'refs/heads/exec/v2.1-pr75-g0-remediation-20260908' ]]
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]
[[ "$(find payload/v21-g0 -maxdepth 1 -type f -name 'overlay.part-*' | wc -l)" == 7 ]]

cat payload/v21-g0/overlay.part-00 \
    payload/v21-g0/overlay.part-01 \
    payload/v21-g0/overlay.part-02 \
    payload/v21-g0/overlay.part-03 \
    payload/v21-g0/overlay.part-04 \
    payload/v21-g0/overlay.part-05 \
    payload/v21-g0/overlay.part-06 \
    > "$RUNNER_TEMP/v21-g0-overlay.b64"
base64 --decode "$RUNNER_TEMP/v21-g0-overlay.b64" > "$RUNNER_TEMP/v21-g0-overlay.tar.gz"
echo "$overlay_sha256  $RUNNER_TEMP/v21-g0-overlay.tar.gz" | sha256sum --check

cat > "$RUNNER_TEMP/expected-paths.txt" <<'PATHS'
README.md
SECURITY.md
crates/heptabao-durable-service/Cargo.toml
crates/heptabao-durable-service/src/lib.rs
crates/heptabao-runtime-service/Cargo.toml
crates/heptabao-runtime-service/src/lib.rs
docs/CURRENT_DOCUMENTATION.md
docs/architecture/HEPTABAO_V2_1_AUTHORIZED_DURABLE_PIPELINE.md
docs/architecture/HEPTABAO_V2_1_DURABLE_RUNTIME_PIPELINE.md
docs/modules/README.md
docs/modules/heptabao-durable-service.md
docs/modules/heptabao-runtime-service.md
planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml
planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml
planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml
scripts/validate_repository_v2.py
tests/repository/test_authorized_durable_runtime_v2_1.py
tests/repository/test_repository_v2.py
PATHS

tar --list --gzip --file "$RUNNER_TEMP/v21-g0-overlay.tar.gz" | sort > "$RUNNER_TEMP/actual-paths.txt"
sort "$RUNNER_TEMP/expected-paths.txt" > "$RUNNER_TEMP/expected-paths.sorted.txt"
diff -u "$RUNNER_TEMP/expected-paths.sorted.txt" "$RUNNER_TEMP/actual-paths.txt"

git fetch origin "$target_branch"
[[ "$(git rev-parse FETCH_HEAD)" == "$source_sha" ]]
git checkout --detach "$source_sha"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]]
tar --extract --gzip --file "$RUNNER_TEMP/v21-g0-overlay.tar.gz" --directory . --no-same-owner --no-same-permissions
python "$GITHUB_WORKSPACE/tools/apply-v21-pr75-g0-remediation.py"
git diff --check

python -m pip install --disable-pip-version-check --requirement requirements-plan.txt
rustup toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy
cargo +1.98.0 generate-lockfile
cargo +1.98.0 fmt --all
git diff --check

python scripts/validate_repository_v2.py
python -m unittest discover -s tests/repository -p 'test_*.py' -v
python -m unittest discover -s tests/security -p 'test_*.py' -v
python scripts/validate_workflow_trust.py
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/plan -p 'test_module_documentation_v1_4_4.py' -v
python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
python -m compileall -q scripts tests

cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.98.0 doc --locked --workspace --no-deps
git diff --check

cp "$RUNNER_TEMP/expected-paths.txt" "$RUNNER_TEMP/allowed-final-paths.txt"
echo Cargo.lock >> "$RUNNER_TEMP/allowed-final-paths.txt"
sort -u "$RUNNER_TEMP/allowed-final-paths.txt" -o "$RUNNER_TEMP/allowed-final-paths.txt"
git status --porcelain=v1 --untracked-files=all | sed -E 's/^...//' | sort -u > "$RUNNER_TEMP/actual-final-paths.txt"
diff -u "$RUNNER_TEMP/allowed-final-paths.txt" "$RUNNER_TEMP/actual-final-paths.txt"

remote_sha="$(git ls-remote origin "refs/heads/$target_branch" | cut -f1)"
[[ "$remote_sha" == "$source_sha" ]]
git config user.name 'HeptaBao G0 convergence controller'
git config user.email 'heptabao-g0@users.noreply.github.com'
git add --all
git commit -m 'fix(v2.1): align repository truth and harden security digests'
git push origin "HEAD:$target_branch"

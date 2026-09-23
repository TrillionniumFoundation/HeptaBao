//! Bounded authenticated workflow management and execution.
//!
//! This is deliberately a small JSON profile rather than a CEL/template
//! engine.  Definitions contain literal, sequential local API requests and
//! explicit response-field mappings.  Every request is dispatched through the
//! normal service dispatcher with the already authenticated principal.  There
//! is no unauthenticated execution, trace output, or crash-resumable step
//! journal in this profile.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const MAX_WORKFLOWS_PER_NAMESPACE: usize = 256;
const MAX_WORKFLOW_PATH_BYTES: usize = 256;
const MAX_WORKFLOW_NAME_BYTES: usize = 64;
const MAX_STEPS: usize = 16;
const MAX_OUTPUTS: usize = 32;
const MAX_FIELD_SELECTOR: usize = 16;
const MAX_JSON_DEPTH: usize = 8;
const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
const MAX_STEP_BODY_BYTES: usize = 64 * 1024;

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) by_namespace: BTreeMap<String, BTreeMap<String, StoredWorkflow>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredWorkflow {
    version: u64,
    definition: WorkflowDefinition,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowDefinition {
    steps: Vec<WorkflowStep>,
    outputs: BTreeMap<String, OutputMapping>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    allow_unauthenticated: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowStep {
    name: String,
    method: String,
    path: String,
    #[serde(default = "empty_object")]
    body: Value,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    allow_failure: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputMapping {
    step: String,
    field: Vec<String>,
}

impl WorkflowState {
    pub(super) fn is_empty(&self) -> bool {
        self.by_namespace.is_empty()
    }

    pub(super) fn has_workflows(&self) -> bool {
        self.by_namespace
            .values()
            .any(|workflows| !workflows.is_empty())
    }

    pub(super) fn namespace_is_empty(&self, namespace: &str) -> bool {
        self.by_namespace
            .get(namespace)
            .is_none_or(BTreeMap::is_empty)
    }

    pub(super) fn validate(&self) -> Result<(), Response> {
        if self.by_namespace.len() > MAX_WORKFLOWS_PER_NAMESPACE.saturating_mul(2) {
            return Err(Response::error(
                503,
                "workflow namespace capacity is exhausted",
            ));
        }
        for (namespace, workflows) in &self.by_namespace {
            if !valid_namespace(namespace) || workflows.len() > MAX_WORKFLOWS_PER_NAMESPACE {
                return Err(Response::error(503, "invalid workflow namespace state"));
            }
            for (path, stored) in workflows {
                validate_workflow_path(path)
                    .map_err(|_| Response::error(503, "invalid persisted workflow path"))?;
                if stored.version == 0 || stored.definition.allow_unauthenticated {
                    return Err(Response::error(503, "invalid persisted workflow version"));
                }
                validate_definition(&stored.definition)?;
            }
        }
        Ok(())
    }

    fn get(&self, namespace: &str, path: &str) -> Option<&StoredWorkflow> {
        self.by_namespace.get(namespace)?.get(path)
    }

    fn put(&mut self, namespace: &str, path: String, stored: StoredWorkflow) {
        self.by_namespace
            .entry(namespace.to_owned())
            .or_default()
            .insert(path, stored);
    }

    fn remove(&mut self, namespace: &str, path: &str) -> Option<StoredWorkflow> {
        let workflows = self.by_namespace.get_mut(namespace)?;
        let removed = workflows.remove(path);
        if workflows.is_empty() {
            self.by_namespace.remove(namespace);
        }
        removed
    }
}

fn validate_name(value: &str, bound: usize) -> bool {
    !value.is_empty()
        && value.len() <= bound
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_workflow_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty()
        || path.len() > MAX_WORKFLOW_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains("\\")
        || path.contains("?")
        || path.contains('#')
        || path.contains("://")
        || path.starts_with("http:")
        || path.starts_with("https:")
        || path.starts_with("file:")
        || !valid_path(path)
        || path == "sys/workflows"
        || path.starts_with("sys/workflows/")
    {
        return Err("workflow paths must be local canonical API paths");
    }
    Ok(())
}

fn bounded_json(value: &Value, depth: usize, bytes: &mut usize) -> Result<(), &'static str> {
    if depth > MAX_JSON_DEPTH {
        return Err("workflow JSON nesting is too deep");
    }
    *bytes = bytes
        .checked_add(
            serde_json::to_vec(value)
                .map_err(|_| "workflow body is not serializable")?
                .len(),
        )
        .ok_or("workflow JSON is too large")?;
    if *bytes > MAX_STEP_BODY_BYTES {
        return Err("workflow step data exceeds the bounded size");
    }
    match value {
        Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
            Err("workflow string exceeds the bounded size")
        }
        Value::Array(values) => {
            if values.len() > 64 {
                return Err("workflow array exceeds the bounded size");
            }
            for value in values {
                bounded_json(value, depth + 1, bytes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > 64 {
                return Err("workflow object exceeds the bounded size");
            }
            for (key, value) in values {
                if key.is_empty() || key.len() > MAX_JSON_STRING_BYTES {
                    return Err("workflow object key exceeds the bounded size");
                }
                bounded_json(value, depth + 1, bytes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn method_value(value: &Value) -> Result<String, Response> {
    let method = value
        .as_str()
        .ok_or_else(|| Response::error(400, "workflow step method must be a string"))?;
    if !matches!(method, "GET" | "LIST" | "POST" | "PUT" | "DELETE") {
        return Err(Response::error(
            400,
            "workflow step method must be GET, LIST, POST, PUT or DELETE",
        ));
    }
    Ok(method.to_owned())
}

fn parse_selector(value: &Value) -> Result<Vec<String>, Response> {
    let fields = match value {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|field| validate_name(field, 128))
                    .map(str::to_owned)
                    .ok_or_else(|| Response::error(400, "workflow output field is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Value::String(value) => value
            .split('.')
            .map(|field| {
                if validate_name(field, 128) {
                    Ok(field.to_owned())
                } else {
                    Err(Response::error(400, "workflow output field is invalid"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(Response::error(
                400,
                "workflow output field must be a string or list",
            ));
        }
    };
    if fields.is_empty() || fields.len() > MAX_FIELD_SELECTOR {
        return Err(Response::error(
            400,
            "workflow output selector is outside bounds",
        ));
    }
    Ok(fields)
}

fn parse_definition(body: &Value) -> Result<(WorkflowDefinition, Option<u64>), Response> {
    let object = body
        .as_object()
        .ok_or_else(|| Response::error(400, "workflow definition must be a JSON object"))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "steps" | "outputs" | "allow_unauthenticated" | "cas"
        )
    }) {
        return Err(Response::error(400, "unknown workflow definition key"));
    }
    let cas =
        match object.get("cas") {
            None => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                Response::error(400, "workflow cas must be a nonnegative integer")
            })?),
        };
    if object
        .get("allow_unauthenticated")
        .is_some_and(|value| value != &Value::Bool(false))
    {
        return Err(Response::error(
            400,
            "allow_unauthenticated=true is not supported",
        ));
    }
    let steps = object
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| Response::error(400, "workflow steps must be an array"))?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err(Response::error(
            400,
            "workflow step count is outside bounds",
        ));
    }
    let mut names = BTreeSet::new();
    let mut parsed_steps = Vec::with_capacity(steps.len());
    for value in steps {
        let object = value
            .as_object()
            .ok_or_else(|| Response::error(400, "workflow step must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "name" | "method" | "operation" | "path" | "body" | "data" | "allow_failure"
            )
        }) {
            return Err(Response::error(400, "unknown workflow step key"));
        }
        if object.contains_key("method") && object.contains_key("operation") {
            return Err(Response::error(
                400,
                "workflow step cannot set both method and operation",
            ));
        }
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| validate_name(name, MAX_WORKFLOW_NAME_BYTES))
            .ok_or_else(|| Response::error(400, "workflow step name is invalid"))?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(Response::error(400, "workflow step names must be unique"));
        }
        let method = object
            .get("method")
            .or_else(|| object.get("operation"))
            .ok_or_else(|| Response::error(400, "workflow step method is required"))
            .and_then(method_value)?;
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Response::error(400, "workflow step path is required"))?;
        validate_workflow_path(path).map_err(|message| Response::error(400, message))?;
        let body = match (object.get("body"), object.get("data")) {
            (Some(_), Some(_)) => {
                return Err(Response::error(
                    400,
                    "workflow step cannot set both body and data",
                ));
            }
            (Some(value), None) | (None, Some(value)) => value.clone(),
            (None, None) => empty_object(),
        };
        if !body.is_object() {
            return Err(Response::error(400, "workflow step body must be an object"));
        }
        let mut bytes = 0;
        bounded_json(&body, 0, &mut bytes).map_err(|message| Response::error(400, message))?;
        let allow_failure = match object.get("allow_failure") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(Response::error(400, "allow_failure must be boolean")),
        };
        parsed_steps.push(WorkflowStep {
            name,
            method,
            path: path.to_owned(),
            body,
            allow_failure,
        });
    }

    let outputs = object
        .get("outputs")
        .and_then(Value::as_object)
        .ok_or_else(|| Response::error(400, "workflow outputs must be an object"))?;
    if outputs.len() > MAX_OUTPUTS {
        return Err(Response::error(
            400,
            "workflow output count is outside bounds",
        ));
    }
    let mut parsed_outputs = BTreeMap::new();
    for (name, value) in outputs {
        if !validate_name(name, MAX_WORKFLOW_NAME_BYTES) {
            return Err(Response::error(400, "workflow output name is invalid"));
        }
        let object = value
            .as_object()
            .ok_or_else(|| Response::error(400, "workflow output mapping must be an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "step" | "field" | "field_selector"))
        {
            return Err(Response::error(400, "unknown workflow output key"));
        }
        if object.contains_key("field") && object.contains_key("field_selector") {
            return Err(Response::error(
                400,
                "workflow output cannot set both field selectors",
            ));
        }
        let step = object
            .get("step")
            .and_then(Value::as_str)
            .filter(|step| names.contains(*step))
            .ok_or_else(|| Response::error(400, "workflow output references an unknown step"))?
            .to_owned();
        let field = object
            .get("field")
            .or_else(|| object.get("field_selector"))
            .ok_or_else(|| Response::error(400, "workflow output field is required"))
            .and_then(parse_selector)?;
        parsed_outputs.insert(name.clone(), OutputMapping { step, field });
    }
    let definition = WorkflowDefinition {
        steps: parsed_steps,
        outputs: parsed_outputs,
        allow_unauthenticated: false,
    };
    validate_definition(&definition)?;
    Ok((definition, cas))
}

fn validate_definition(definition: &WorkflowDefinition) -> Result<(), Response> {
    if definition.allow_unauthenticated
        || definition.steps.is_empty()
        || definition.steps.len() > MAX_STEPS
        || definition.outputs.len() > MAX_OUTPUTS
    {
        return Err(Response::error(
            503,
            "persisted workflow definition is invalid",
        ));
    }
    let mut names = BTreeSet::new();
    for step in &definition.steps {
        if !validate_name(&step.name, MAX_WORKFLOW_NAME_BYTES)
            || !names.insert(step.name.as_str())
            || !matches!(
                step.method.as_str(),
                "GET" | "LIST" | "POST" | "PUT" | "DELETE"
            )
        {
            return Err(Response::error(503, "persisted workflow step is invalid"));
        }
        validate_workflow_path(&step.path)
            .map_err(|_| Response::error(503, "persisted workflow path is invalid"))?;
        if !step.body.is_object() {
            return Err(Response::error(503, "persisted workflow body is invalid"));
        }
        let mut bytes = 0;
        bounded_json(&step.body, 0, &mut bytes)
            .map_err(|_| Response::error(503, "persisted workflow body is too large"))?;
    }
    for (name, output) in &definition.outputs {
        if !validate_name(name, MAX_WORKFLOW_NAME_BYTES)
            || !names.contains(output.step.as_str())
            || output.field.is_empty()
            || output.field.len() > MAX_FIELD_SELECTOR
            || output.field.iter().any(|field| !validate_name(field, 128))
        {
            return Err(Response::error(503, "persisted workflow output is invalid"));
        }
    }
    Ok(())
}

fn route_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix)?.strip_prefix('/')
}

fn mapped_value<'a>(value: &'a Value, fields: &[String]) -> Option<&'a Value> {
    let mut current = value;
    for field in fields {
        current = match current {
            Value::Object(values) => values.get(field)?,
            Value::Array(values) => values.get(field.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn definition_value(definition: &WorkflowDefinition) -> Result<Value, Response> {
    serde_json::to_value(definition)
        .map_err(|_| Response::error(500, "workflow definition serialization failed"))
}

impl Service {
    pub(super) fn workflows_handles(path: &str) -> bool {
        path == "sys/workflows/manage"
            || path.starts_with("sys/workflows/manage/")
            || path.starts_with("sys/workflows/execute/")
    }

    pub(super) fn workflow_route(
        &mut self,
        mut state: State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if !state.namespace_exists(request.namespace) {
            return Response::error(404, "request namespace not found");
        }
        if request.wrap_ttl_seconds.is_some() {
            return Response::error(501, "workflow responses cannot be wrapped");
        }

        let management = request.path == "sys/workflows/manage"
            || request.path.starts_with("sys/workflows/manage/");
        if management {
            let capability = match request.method {
                "LIST" => "list",
                "GET" => "read",
                "POST" => "update",
                "DELETE" => "delete",
                _ => return Response::error(405, "unsupported workflow management method"),
            };
            if let Err(error) = state.auth.authorize_sudo_request(
                principal,
                request.namespace,
                request.path,
                capability,
                request.now,
            ) {
                return Response::error(error.status, &error.message);
            }
            let suffix = if request.path == "sys/workflows/manage" {
                None
            } else {
                route_suffix(request.path, "sys/workflows/manage")
            };
            if suffix.is_some_and(|value| value.is_empty()) {
                return Response::error(400, "workflow path is required");
            }
            return match request.method {
                "LIST" => Self::workflow_list(&state, request.namespace, suffix),
                "GET" => {
                    let Some(path) = suffix else {
                        return Response::error(400, "workflow path is required");
                    };
                    let path = match validate_workflow_path(path) {
                        Ok(()) => path,
                        Err(message) => return Response::error(400, message),
                    };
                    let Some(stored) = state.namespaces.workflows.get(request.namespace, path)
                    else {
                        return Response::error(404, "workflow not found");
                    };
                    let definition = match definition_value(&stored.definition) {
                        Ok(value) => value,
                        Err(error) => return error,
                    };
                    Response::ok(
                        json!({"data":{"path":path,"version":stored.version,"workflow":definition}}),
                    )
                }
                "POST" => {
                    let Some(path) = suffix else {
                        return Response::error(400, "workflow path is required");
                    };
                    let path = match validate_workflow_path(path) {
                        Ok(()) => path.to_owned(),
                        Err(message) => return Response::error(400, message),
                    };
                    let (definition, cas) = match parse_definition(request.body) {
                        Ok(value) => value,
                        Err(error) => return error,
                    };
                    let existing = state.namespaces.workflows.get(request.namespace, &path);
                    let version = match (existing, cas) {
                        (Some(_), Some(0)) => {
                            return Response::error(409, "workflow already exists");
                        }
                        (None, Some(expected)) if expected != 0 => {
                            return Response::error(409, "workflow CAS version does not exist");
                        }
                        (Some(current), Some(expected)) if current.version != expected => {
                            return Response::error(409, "workflow CAS version mismatch");
                        }
                        (Some(current), _) => match current.version.checked_add(1) {
                            Some(version) => version,
                            None => return Response::error(507, "workflow version exhausted"),
                        },
                        (None, _) => 1,
                    };
                    if version == 0 {
                        return Response::error(507, "workflow version exhausted");
                    }
                    state.namespaces.workflows.put(
                        request.namespace,
                        path.clone(),
                        StoredWorkflow {
                            version,
                            definition,
                        },
                    );
                    state.schema = CURRENT_STATE_SCHEMA;
                    if let Err(error) = state.validate_format() {
                        return error;
                    }
                    if let Err(error) = self.commit_state(&state) {
                        return error;
                    }
                    self.state = Some(state);
                    Response::ok(json!({"data":{"path":path,"version":version}}))
                }
                "DELETE" => {
                    let Some(path) = suffix else {
                        return Response::error(400, "workflow path is required");
                    };
                    let path = match validate_workflow_path(path) {
                        Ok(()) => path,
                        Err(message) => return Response::error(400, message),
                    };
                    let cas = match request.body.as_object() {
                        Some(object) if object.keys().all(|key| key == "cas") => {
                            match object.get("cas") {
                                None => None,
                                Some(value) => match value.as_u64() {
                                    Some(value) => Some(value),
                                    None => {
                                        return Response::error(
                                            400,
                                            "workflow cas must be a nonnegative integer",
                                        );
                                    }
                                },
                            }
                        }
                        Some(object) if object.is_empty() => None,
                        _ => return Response::error(400, "workflow delete accepts only cas"),
                    };
                    let Some(current) = state.namespaces.workflows.get(request.namespace, path)
                    else {
                        return Response::error(404, "workflow not found");
                    };
                    if cas.is_some_and(|expected| expected == 0 || expected != current.version) {
                        return Response::error(409, "workflow CAS version mismatch");
                    }
                    state.namespaces.workflows.remove(request.namespace, path);
                    state.schema = CURRENT_STATE_SCHEMA;
                    if let Err(error) = state.validate_format() {
                        return error;
                    }
                    if let Err(error) = self.commit_state(&state) {
                        return error;
                    }
                    self.state = Some(state);
                    Response {
                        status: 204,
                        body: Value::Null,
                    }
                }
                _ => unreachable!(),
            };
        }

        if request.method != "POST" {
            return Response::error(405, "workflow execution requires POST");
        }
        if let Err(error) = state.auth.authorize_request(
            principal,
            request.namespace,
            request.path,
            "update",
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        let Some(path) = route_suffix(request.path, "sys/workflows/execute") else {
            return Response::error(400, "workflow path is required");
        };
        let path = match validate_workflow_path(path) {
            Ok(()) => path,
            Err(message) => return Response::error(400, message),
        };
        let Some(stored) = state
            .namespaces
            .workflows
            .get(request.namespace, path)
            .cloned()
        else {
            return Response::error(404, "workflow not found");
        };
        if request
            .body
            .as_object()
            .is_none_or(|object| !object.is_empty())
        {
            return Response::error(400, "workflow execution accepts an empty JSON object");
        }
        let mut responses = BTreeMap::<String, Value>::new();
        let mut approle_secret_consumption = None;
        for step in &stored.definition.steps {
            if self.workflow_step_is_nonlocal(&state, request.namespace, step) {
                return Response::error(400, "workflow steps must target local transactional APIs");
            }
            let response = Self::dispatch_authorized_subrequest(
                &mut state,
                Some(principal),
                request.namespace,
                &step.method,
                &step.path,
                &step.body,
                request.now,
                request.client_certificates,
                request.origin_peer,
                &mut approle_secret_consumption,
            );
            if approle_secret_consumption.is_some() {
                return Response::error(400, "workflow authentication login steps are unsupported");
            }
            if response.status >= 300 && !step.allow_failure {
                return response;
            }
            responses.insert(step.name.clone(), response.body.clone());
        }

        let mut outputs = serde_json::Map::new();
        for (name, mapping) in &stored.definition.outputs {
            if let Some(response) = responses.get(&mapping.step)
                && let Some(value) = mapped_value(response, &mapping.field)
            {
                outputs.insert(name.clone(), value.clone());
            }
        }
        let changed = self.state.as_ref().is_some_and(|previous| {
            !state.namespaces.ptr_eq(&previous.namespaces)
                || !state.auth.ptr_eq(&previous.auth)
                || !state.engines.ptr_eq(&previous.engines)
                || !state.database.ptr_eq(&previous.database)
                || !state.raft_admin.ptr_eq(&previous.raft_admin)
        });
        if changed {
            state.schema = CURRENT_STATE_SCHEMA;
            if let Err(error) = state.validate_format() {
                return error;
            }
            if let Err(error) = self.commit_state(&state) {
                return error;
            }
            self.state = Some(state);
        }
        Response::ok(json!({"data":outputs}))
    }

    fn workflow_step_is_nonlocal(
        &self,
        state: &State,
        namespace: &str,
        step: &WorkflowStep,
    ) -> bool {
        let external_mount = matches!(step.method.as_str(), "POST" | "PUT")
            && step.path.starts_with("sys/mounts/")
            && matches!(
                step.body.get("type").and_then(Value::as_str),
                Some("database" | "rabbitmq" | "ldap" | "kubernetes" | "plugin")
            );
        step.path == "sys/workflows"
            || step.path.starts_with("sys/workflows/")
            || step.path == "sys/audit"
            || step.path.starts_with("sys/audit/")
            || step.path == "sys/internal/audit/file"
            || Self::is_raft_admin_path(&step.path)
            || Self::plugin_catalog_handles(&step.path)
            || external_mount
            || self.database_handles(state, namespace, &step.path, &step.body)
            || Self::openldap_handles(state, namespace, &step.path, &step.body)
            || Self::kubernetes_secret_handles(state, namespace, &step.path)
            || Self::plugin_kms_handles(&step.path)
            || self.plugin_secret_handles(state, namespace, &step.path)
    }

    fn workflow_list(state: &State, namespace: &str, prefix: Option<&str>) -> Response {
        let prefix = match prefix {
            None => "",
            Some(prefix) => match validate_workflow_path(prefix) {
                Ok(()) => prefix,
                Err(message) => return Response::error(400, message),
            },
        };
        let mut keys = BTreeSet::new();
        let mut key_info = serde_json::Map::new();
        if let Some(workflows) = state.namespaces.workflows.by_namespace.get(namespace) {
            for path in workflows.keys() {
                let Some(relative) = path.strip_prefix(prefix) else {
                    continue;
                };
                let relative = relative.strip_prefix('/').unwrap_or(relative);
                if relative.is_empty() {
                    continue;
                }
                let key = if let Some((child, _)) = relative.split_once('/') {
                    format!("{child}/")
                } else {
                    relative.to_owned()
                };
                if keys.insert(key.clone()) {
                    let absolute = if prefix.is_empty() {
                        key.trim_end_matches('/').to_owned()
                    } else {
                        format!("{prefix}/{}", key.trim_end_matches('/'))
                    };
                    if let Some(entry) = workflows.get(&absolute) {
                        key_info.insert(key, json!({"version":entry.version}));
                    } else {
                        key_info.insert(key, json!({"prefix":true}));
                    }
                }
            }
        }
        Response::ok(json!({"data":{"keys":keys,"key_info":key_info}}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use super::super::tests::{Root, bootstrap, call};

    #[test]
    fn definition_rejects_external_recursive_and_unknown_shapes() {
        let base = json!({
            "steps":[{"name":"read","method":"GET","path":"secret/data/item"}],
            "outputs":{"value":{"step":"read","field":["data","value"]}}
        });
        assert!(parse_definition(&base).is_ok());
        for path in [
            "https://example.test/x",
            "../secret",
            "sys/workflows/execute/x",
        ] {
            let mut value = base.clone();
            value["steps"][0]["path"] = json!(path);
            assert!(parse_definition(&value).is_err(), "{path}");
        }
        let mut unknown = base;
        unknown["unexpected"] = json!(true);
        assert!(parse_definition(&unknown).is_err());
    }

    #[test]
    fn cas_versions_are_monotonic_and_zero_is_create_only() -> Result<(), &'static str> {
        let (definition, _) = parse_definition(&json!({
            "steps":[{"name":"read","method":"GET","path":"secret/data/item"}],
            "outputs":{}
        }))
        .map_err(|_| "definition")?;
        let first = StoredWorkflow {
            version: 1,
            definition,
        };
        let mut state = WorkflowState::default();
        state.put("", "operations/demo".into(), first);
        assert_eq!(state.get("", "operations/demo").map(|v| v.version), Some(1));
        assert!(
            parse_definition(&json!({
                "steps":[{"name":"read","method":"GET","path":"secret/data/item"}],
                "outputs":{},"cas":"one"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn authenticated_workflow_is_scoped_durable_and_executes_in_one_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let _ = std::fs::remove_dir_all(&root.path);
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/mounts/workflow-kv",
                &token,
                json!({"type":"kv","options":{"version":"2"}}),
            )
            .status,
            204
        );
        let definition = json!({
            "cas": 0,
            "steps": [
                {"name":"write","method":"POST","path":"workflow-kv/data/item","body":{"data":{"value":"bounded"}}},
                {"name":"read","method":"GET","path":"workflow-kv/data/item"}
            ],
            "outputs": {"value":{"step":"read","field":["data","data","value"]}}
        });
        let created = call(
            &mut service,
            "POST",
            "sys/workflows/manage/operations/demo",
            &token,
            definition,
        );
        assert_eq!(created.status, 200);
        assert_eq!(created.body["data"]["version"], 1);
        let listed = call(
            &mut service,
            "LIST",
            "sys/workflows/manage",
            &token,
            json!({}),
        );
        assert_eq!(listed.status, 200);
        assert_eq!(listed.body["data"]["keys"], json!(["operations/"]));
        let executed = call(
            &mut service,
            "POST",
            "sys/workflows/execute/operations/demo",
            &token,
            json!({}),
        );
        assert_eq!(executed.status, 200);
        assert_eq!(executed.body["data"]["value"], "bounded");
        let conflict = call(
            &mut service,
            "POST",
            "sys/workflows/manage/operations/demo",
            &token,
            json!({"cas":1,"steps":[],"outputs":{}}),
        );
        assert_eq!(conflict.status, 400);

        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let stored = call(
            &mut reopened,
            "GET",
            "sys/workflows/manage/operations/demo",
            &token,
            json!({}),
        );
        assert_eq!(stored.status, 200);
        assert_eq!(stored.body["data"]["version"], 1);
        Ok(())
    }
}

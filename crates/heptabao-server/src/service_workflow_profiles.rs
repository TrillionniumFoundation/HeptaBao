//! Static HCL profiles use the normal request interpreter and durable approval owner.
//! CEL, templates, unauthenticated execution and trace remain separate capabilities.
use super::*;
use crate::auth::{Lex, lex_hcl, parse_hcl_value};
#[path = "service_workflow_dynamic.rs"]
pub(super) mod dynamic;
#[path = "service_workflow_credentials.rs"]
mod credentials;

const MAX_PROFILE_BYTES: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    document: String,
    description: String,
    cas_required: bool,
}

pub(super) struct Compiled {
    steps: Vec<WorkflowStep>,
    output: Value,
}

fn bad_profile(message: &str) -> Response {
    Response::error(400, message)
}
fn symbol(tokens: &[Lex], cursor: &mut usize, symbol: char) -> Result<(), Response> {
    if tokens.get(*cursor) != Some(&Lex::Symbol(symbol)) {
        return Err(bad_profile("malformed workflow profile block"));
    }
    *cursor += 1;
    Ok(())
}
fn label(tokens: &[Lex], cursor: &mut usize) -> Result<String, Response> {
    let Some(Lex::String(label)) = tokens.get(*cursor) else {
        return Err(bad_profile("workflow profile block requires a quoted name"));
    };
    if !validate_name(label, MAX_WORKFLOW_NAME_BYTES) {
        return Err(bad_profile("invalid workflow profile name"));
    }
    *cursor += 1;
    Ok(label.clone())
}
fn attributes(tokens: &[Lex], cursor: &mut usize) -> Result<Value, Response> {
    parse_hcl_value(tokens, cursor).map_err(|_| bad_profile("invalid static workflow attributes"))
}
fn step_key(flow: &str, name: &str) -> String {
    format!("{flow}/{name}")
}

impl Profile {
    pub(super) fn document(&self) -> &str { &self.document }
    pub(super) fn has_logical_data(&self) -> bool {
        self.dynamic_program().ok().flatten().is_some_and(|program| program.has_logical_data())
    }
    pub(super) fn has_expression_sources(&self) -> bool {
        self.dynamic_program().ok().flatten().is_some_and(|program| program.has_expression_sources())
    }
    pub(super) fn has_request_credentials(&self) -> bool {
        self.dynamic_program().ok().flatten().is_some_and(|program| program.has_request_credentials())
    }

    pub(super) fn dynamic_program(&self) -> Result<Option<dynamic::Program>, Response> {
        if self.description.len() > MAX_JSON_STRING_BYTES {
            return Err(bad_profile("workflow description is outside bounds"));
        }
        dynamic::Program::compile(&self.document)
    }
    pub(super) fn wire(&self, path: &str, version: u64) -> Value {
        json!({"path":path, "version":version, "workflow":self.document,
            "description":self.description, "cas_required":self.cas_required,
            "allow_unauthenticated":false})
    }

    pub(super) fn compile(&self) -> Result<Compiled, Response> {
        if self.document.is_empty()
            || self.document.len() > MAX_PROFILE_BYTES
            || self.description.len() > MAX_JSON_STRING_BYTES
        {
            return Err(bad_profile("workflow profile text is outside bounds"));
        }
        let tokens = lex_hcl(&self.document)
            .map_err(|_| bad_profile("unsupported or malformed static HCL workflow"))?;
        // Bound nesting before the shared recursive HCL value parser enters
        // any request data or output. The document byte limit alone does not
        // bound stack depth for deeply nested static input.
        let mut nesting = 0usize;
        for token in &tokens {
            match token {
                Lex::Symbol('{' | '[') => {
                    nesting += 1;
                    if nesting > MAX_JSON_DEPTH + 3 {
                        return Err(bad_profile("workflow profile nesting is outside bounds"));
                    }
                }
                Lex::Symbol('}' | ']') => nesting = nesting.saturating_sub(1),
                _ => {}
            }
        }
        let mut cursor = 0;
        let mut flows = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut steps = Vec::new();
        let mut output = None;
        while cursor < tokens.len() {
            match tokens.get(cursor) {
                Some(Lex::Word(word)) if word == "flow" => {
                    cursor += 1;
                    let flow = label(&tokens, &mut cursor)?;
                    if !flows.insert(flow.clone()) {
                        return Err(bad_profile("duplicate workflow flow"));
                    }
                    symbol(&tokens, &mut cursor, '{')?;
                    let first = steps.len();
                    while tokens.get(cursor) != Some(&Lex::Symbol('}')) {
                        if tokens.get(cursor) != Some(&Lex::Word("request".into())) {
                            return Err(bad_profile("unsupported workflow flow statement"));
                        }
                        cursor += 1;
                        let name = label(&tokens, &mut cursor)?;
                        let name = step_key(&flow, &name);
                        if !names.insert(name.clone()) || steps.len() >= MAX_STEPS {
                            return Err(bad_profile("duplicate or excessive workflow request"));
                        }
                        let attrs = attributes(&tokens, &mut cursor)?;
                        let attrs = attrs
                            .as_object()
                            .ok_or_else(|| bad_profile("workflow request must be an object"))?;
                        if attrs.keys().any(|key| {
                            !matches!(
                                key.as_str(),
                                "operation" | "path" | "data" | "allow_failure"
                            )
                        }) {
                            return Err(bad_profile("unsupported workflow request attribute"));
                        }
                        let operation = attrs
                            .get("operation")
                            .and_then(Value::as_str)
                            .ok_or_else(|| bad_profile("workflow operation is required"))?;
                        let method = match operation {
                            "read" => "GET",
                            "list" => "LIST",
                            "create" | "update" => "POST",
                            "delete" => "DELETE",
                            "patch" => "PATCH",
                            "scan" => "SCAN",
                            _ => return Err(bad_profile("unsupported workflow operation")),
                        };
                        let path = attrs
                            .get("path")
                            .and_then(Value::as_str)
                            .ok_or_else(|| bad_profile("workflow request path is required"))?;
                        validate_workflow_path(path).map_err(bad_profile)?;
                        let body = attrs.get("data").cloned().unwrap_or_else(empty_object);
                        if !body.is_object() {
                            return Err(bad_profile("workflow request data must be an object"));
                        }
                        let mut bytes = 0;
                        bounded_json(&body, 0, &mut bytes).map_err(bad_profile)?;
                        let allow_failure = match attrs.get("allow_failure") {
                            None => false,
                            Some(Value::Bool(value)) => *value,
                            _ => return Err(bad_profile("workflow allow_failure must be boolean")),
                        };
                        steps.push(WorkflowStep {
                            name,
                            method: method.into(),
                            path: path.into(),
                            body,
                            allow_failure,
                        });
                    }
                    cursor += 1;
                    if first == steps.len() {
                        return Err(bad_profile("workflow flow has no requests"));
                    }
                }
                Some(Lex::Word(word)) if word == "output" => {
                    cursor += 1;
                    if output.is_some() {
                        return Err(bad_profile("duplicate workflow output block"));
                    }
                    let attrs = attributes(&tokens, &mut cursor)?;
                    let attrs = attrs
                        .as_object()
                        .ok_or_else(|| bad_profile("workflow output must be an object"))?;
                    if attrs.keys().any(|key| key != "data") {
                        return Err(bad_profile("unsupported workflow output attribute"));
                    }
                    output = Some(attrs.get("data").cloned().unwrap_or_else(empty_object));
                }
                _ => return Err(bad_profile("unsupported workflow profile statement")),
            }
        }
        if steps.is_empty() {
            return Err(bad_profile("workflow profile has no requests"));
        }
        let output = output.unwrap_or_else(empty_object);
        if !output.is_object() {
            return Err(bad_profile("workflow output data must be an object"));
        }
        let mut bytes = 0;
        bounded_json(&output, 0, &mut bytes).map_err(bad_profile)?;
        validate_output(&output, &names, 0)?;
        Ok(Compiled { steps, output })
    }
}

fn response_expression(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("eval_source"))
}
fn validate_output(value: &Value, names: &BTreeSet<String>, depth: usize) -> Result<(), Response> {
    if depth > MAX_JSON_DEPTH {
        return Err(bad_profile("workflow output nesting is outside bounds"));
    }
    if response_expression(value) {
        let object = value
            .as_object()
            .ok_or_else(|| bad_profile("workflow response source must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "eval_source" | "eval_type" | "flow_name" | "response_name" | "field_selector"
            )
        }) || object.get("eval_source").and_then(Value::as_str) != Some("response")
            || !matches!(
                object.get("eval_type").and_then(Value::as_str),
                Some(
                    "interface{}"
                        | "string"
                        | "bool"
                        | "int"
                        | "float64"
                        | "map[string]interface{}"
                )
            )
        {
            return Err(bad_profile("unsupported workflow output expression"));
        }
        let flow = object
            .get("flow_name")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_profile("workflow response flow is required"))?;
        let response = object
            .get("response_name")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_profile("workflow response name is required"))?;
        if !names.contains(&step_key(flow, response)) {
            return Err(bad_profile("workflow response source is unknown"));
        }
        if let Some(selector) = object.get("field_selector") {
            let selector = selector
                .as_array()
                .ok_or_else(|| bad_profile("workflow field_selector must be an array"))?;
            if selector.len() > MAX_FIELD_SELECTOR
                || selector
                    .iter()
                    .any(|item| item.as_str().is_none_or(|field| !validate_name(field, 128)))
            {
                return Err(bad_profile("workflow field_selector is outside bounds"));
            }
        }
        return Ok(());
    }
    match value {
        Value::Object(object) => {
            for item in object.values() {
                validate_output(item, names, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for item in array {
                validate_output(item, names, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn evaluate_output(value: &Value, responses: &BTreeMap<String, Value>) -> Result<Value, Response> {
    if response_expression(value) {
        let flow = value["flow_name"]
            .as_str()
            .ok_or_else(|| bad_profile("invalid response flow"))?;
        let name = value["response_name"]
            .as_str()
            .ok_or_else(|| bad_profile("invalid response name"))?;
        let mut selected = responses
            .get(&step_key(flow, name))
            .ok_or_else(|| bad_profile("workflow response is unavailable"))?;
        if let Some(fields) = value.get("field_selector").and_then(Value::as_array) {
            for field in fields {
                let field = field
                    .as_str()
                    .ok_or_else(|| bad_profile("invalid response selector"))?;
                selected = match selected {
                    Value::Object(object) => object.get(field),
                    Value::Array(array) => field
                        .parse::<usize>()
                        .ok()
                        .and_then(|index| array.get(index)),
                    _ => None,
                }
                .ok_or_else(|| bad_profile("workflow response field is unavailable"))?;
            }
        }
        let valid = match value["eval_type"].as_str() {
            Some("interface{}") => true,
            Some("string") => selected.is_string(),
            Some("bool") => selected.is_boolean(),
            Some("int") => selected.as_i64().is_some() || selected.as_u64().is_some(),
            Some("float64") => selected.is_number(),
            Some("map[string]interface{}") => selected.is_object(),
            _ => false,
        };
        return if valid {
            Ok(selected.clone())
        } else {
            Err(bad_profile("workflow response type mismatch"))
        };
    }
    match value {
        Value::Object(object) => {
            let mut result = serde_json::Map::new();
            for (key, item) in object {
                result.insert(key.clone(), evaluate_output(item, responses)?);
            }
            Ok(Value::Object(result))
        }
        Value::Array(array) => array
            .iter()
            .map(|item| evaluate_output(item, responses))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn echo_admitted_token_reply(response: &mut Response, path: &str, body: &Value, token: &str) {
    if response.status != 200 {
        return;
    }
    // The ordinary auth dispatcher has admitted the exact target. This only
    // returns caller-supplied bytes; it creates no principal or durable bearer.
    let renewed = match path {
        "auth/token/renew-self" => Some(token),
        "auth/token/renew" => body.get("token").and_then(Value::as_str),
        _ => None,
    };
    if let (Some(raw), Some(auth)) = (
        renewed,
        response.body.get_mut("auth").and_then(Value::as_object_mut),
    ) {
        auth.insert("client_token".into(), json!(raw));
    }
    let looked_up = match path {
        "auth/token/lookup-self" => Some(token),
        "auth/token/lookup" => Some(
            body.get("token")
                .and_then(Value::as_str)
                .filter(|raw| !raw.is_empty())
                .unwrap_or(token),
        ),
        "auth/token/lookup-accessor" => Some(""),
        _ => None,
    };
    if let (Some(raw), Some(data)) = (
        looked_up,
        response.body.get_mut("data").and_then(Value::as_object_mut),
    ) {
        data.insert("id".into(), json!(raw));
    }
}

impl Service {
    pub(super) fn workflow_profile_manage(
        &mut self,
        mut state: State,
        request: &RequestView<'_>,
        path: String,
    ) -> Response {
        let Some(object) = request.body.as_object() else {
            return bad_profile("workflow management requires an object");
        };
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "workflow" | "description" | "cas" | "cas_required" | "allow_unauthenticated"
            )
        }) {
            return bad_profile("unknown profile workflow management field");
        }
        let Some(document) = object.get("workflow").and_then(Value::as_str) else {
            return bad_profile("workflow profile must be a string");
        };
        let description = match object.get("description") {
            None => "",
            Some(Value::String(value)) => value,
            _ => return bad_profile("workflow description must be a string"),
        };
        let cas_required = match object.get("cas_required") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return bad_profile("workflow cas_required must be boolean"),
        };
        if object
            .get("allow_unauthenticated")
            .is_some_and(|value| value != &Value::Bool(false))
        {
            return bad_profile(
                "unauthenticated profiles require an explicit admission capability",
            );
        }
        let profile = Profile {
            document: document.into(),
            description: description.into(),
            cas_required,
        };
        let dynamic_sources = match profile.dynamic_program() {
            Ok(Some(_)) => true,
            Ok(None) => {
                if let Err(error) = profile.compile() {
                    return error;
                }
                false
            }
            Err(error) => return error,
        };
        let cas = match object.get("cas") {
            None => None,
            Some(value) => match value.as_i64() {
                Some(value) if value >= -1 => Some(value),
                _ => return bad_profile("workflow cas must be an integer at least -1"),
            },
        };
        let current = state.namespaces.workflows.get(request.namespace, &path);
        if current.is_some_and(|entry| {
            entry
                .definition
                .profile
                .as_ref()
                .is_some_and(|profile| profile.cas_required)
        }) && cas.is_none_or(|value| value < 0)
        {
            return bad_profile("workflow requires an explicit CAS version");
        }
        if let Some(expected) = cas.filter(|value| *value >= 0) {
            let actual = current.map_or(0, |entry| entry.version);
            if u64::try_from(expected).ok() != Some(actual) {
                return Response::error(409, "workflow CAS version mismatch");
            }
        }
        let version = match current.map_or(Some(1), |entry| entry.version.checked_add(1)) {
            Some(version) => version,
            None => return Response::error(507, "workflow version exhausted"),
        };
        let wire = profile.wire(&path, version);
        state.namespaces.workflows.put(
            request.namespace,
            path,
            StoredWorkflow {
                version,
                definition: WorkflowDefinition {
                    dynamic_sources,
                    profile: Some(profile),
                    steps: Vec::new(),
                    outputs: BTreeMap::new(),
                    allow_unauthenticated: false,
                },
            },
        );
        if let Err(error) = self.control_group_publish(&mut state) {
            return error;
        }
        Response::ok(json!({"data":wire}))
    }

    pub(super) fn workflow_profile_execute(
        &mut self,
        mut state: State,
        actor: &Principal,
        outer: &RequestView<'_>,
        profile: &Profile,
    ) -> Response {
        let compiled = match profile.compile() {
            Ok(compiled) => compiled,
            Err(error) => return error,
        };
        let mut responses = BTreeMap::new();
        for step in &compiled.steps {
            // Static requests declare no inner logical headers or query. The
            // outer HTTP frame belongs to execute, never to this subrequest.
            let _logical_data = match crate::request_metadata::Scope::enter(
                None, &step.method, &step.path, outer.namespace, &step.body,
            ) {
                Ok(scope) => scope,
                Err(error) => return Response::error(400, error),
            };
            let mut response = self.workflow_profile_dispatch_step(&mut state, actor, outer, step);
            if response.status >= 300 && !step.allow_failure {
                return response;
            }
            responses.insert(step.name.clone(), std::mem::take(&mut response.body));
        }
        match evaluate_output(&compiled.output, &responses) {
            Ok(output) => Response::ok(json!({"data":output})),
            Err(error) => error,
        }
    }

    fn workflow_profile_dispatch_step(
        &mut self,
        state: &mut State,
        actor: &Principal,
        outer: &RequestView<'_>,
        step: &WorkflowStep,
    ) -> Response {
        if self.workflow_step_is_nonlocal(state, outer.namespace, step) {
            return bad_profile("profile request requires an unsupported external effect boundary");
        }
        let envelopes = match request_normalization::envelopes(&step.method, &step.path, &step.body)
        {
            Ok(value) => value,
            Err(error) => return error,
        };
        let root = request_normalization::kv_root(
            Some(state),
            outer.namespace,
            &step.method,
            &step.path,
            envelopes.body,
        );
        let normalized = match request_normalization::operation(
            Some(state),
            outer.namespace,
            &step.method,
            root.as_deref().unwrap_or(&step.path),
            &step.path,
            envelopes.body,
        ) {
            Ok(value) => value,
            Err(error) => return error,
        };
        let namespace =
            request_normalization::token_namespace(&normalized.path, Some(actor.namespace()))
                .unwrap_or(outer.namespace);
        if namespace != outer.namespace {
            return Response::error(
                403,
                "profile request cannot change the admitted namespace view",
            );
        }
        let request = RequestView {
            method: &normalized.method,
            path: &normalized.path,
            namespace,
            token: outer.token,
            body: &normalized.body.0,
            now: outer.now,
            admission_started: outer.admission_started,
            token_clock: outer.token_clock,
            allow_forward: outer.allow_forward,
            enforce_namespace: outer.enforce_namespace,
            wrap_ttl_seconds: None,
            origin_peer: outer.origin_peer,
            client_certificates: outer.client_certificates,
        };
        let logical_data = match crate::request_metadata::current(
            &step.method,&step.path,outer.namespace,&step.body) {
            Ok(frame) => frame,
            Err(error) => return Response::error(400,error),
        };
        let _logical_data = match crate::request_metadata::Scope::enter(logical_data,
            request.method,request.path,request.namespace,request.body) {
            Ok(scope) => scope,
            Err(error) => return Response::error(400,error),
        };
        let transport = control_groups::TransportRequest {
            method: &step.method,
            path: &step.path,
            namespace: outer.namespace,
            body: &step.body,
        };
        let deferred = self.control_group_route(state, Some(actor), &request, transport, false);
        let response = if let Some(response) = deferred {
            response
        } else {
            let mut consumption = None;
            let mut response = Self::dispatch_authorized_subrequest(
                state,
                Some(actor),
                namespace,
                request.method,
                request.path,
                request.body,
                envelopes.token_fields.as_ref(),
                envelopes.pki_role_fields.as_ref(),
                outer.now,
                outer.token_clock,
                outer.client_certificates,
                outer.origin_peer,
                &mut consumption,
            );
            echo_admitted_token_reply(&mut response, request.path, request.body, outer.token);
            if consumption.is_some() {
                return bad_profile(
                    "profile authentication login requires an affine consumption boundary",
                );
            }
            if response.status < 300 {
                // Each ordinary inner request commits before the next one.
                // Approval deferral has already published its inert owner.
                if let Err(error) = self.control_group_publish(state) {
                    return error;
                }
            }
            response
        };
        // Refresh without dropping the prepared namespace capsule installed
        // by the commit. No outer approval authorizes a different inner API.
        if let Some(current) = &self.state {
            *state = current.clone();
            state.namespace_protected = current.namespace_protected.clone();
        }
        response
    }

    pub(super) fn workflow_dynamic_profile_execute(
        &mut self,
        mut state: State,
        actor: &Principal,
        outer: &RequestView<'_>,
        profile: &Profile,
    ) -> Response {
        let program = match profile.dynamic_program() {
            Ok(Some(program)) => program,
            _ => return bad_profile("persisted dynamic workflow program is unavailable"),
        };
        let mut context = match program.context_at(outer.body, outer.admission_started) {
            Ok(context) => context,
            Err(error) => return error,
        };
        for step in &program.steps {
            let resolved = match step.resolve(&context) {
                Ok(Some(resolved)) => resolved,
                Ok(None) => continue,
                Err(error) => return error,
            };
            let _logical_data = match crate::request_metadata::Scope::enter(
                resolved.data_frame.clone(), &resolved.step.method, &resolved.step.path,
                outer.namespace, &resolved.step.body) {
                Ok(scope) => scope,
                Err(message) => return Response::error(400,message),
            };
            let mut response = match &resolved.token {
                Some(token) => self.workflow_credential_dispatch_step(&mut state, outer, &resolved.step, token),
                None => self.workflow_profile_dispatch_step(&mut state, actor, outer, &resolved.step),
            };
            // An actual retained provider owner or affine delivery fence is
            // terminal even when the profile permits ordinary API failures.
            if self.pending_workflow_external_hold.is_some() || self.recovery_required {
                if response.status < 500 {
                    erase_json(&mut response.body);
                    return Response::error(503, "workflow request owns an unresolved terminal boundary");
                }
                return response;
            }
            if response.status >= 300 && !resolved.step.allow_failure {
                return response;
            }
            context.record_response(resolved, &mut response);
        }
        let output = match program.runtime_output(&context) {
            Ok(output) => output,
            Err(error) => return error,
        };
        if output.has_nonfinite() {
            // Official2.7 fails response wrapping at the final output stage,
            // after already committed requests. Never mint a finite wrapper
            // for an internally evaluated value that JSON cannot represent.
            if outer.wrap_ttl_seconds.is_some_and(|ttl|ttl>0) {
                return Response::error(500,"internal error");
            }
            let output=match crate::workflow_runtime::FailedOutput::capture(output) {
                Ok(output)=>output,
                Err(())=>return Response::error(500,"workflow output representation rejected"),
            };
            let mut response=Response::ok(crate::workflow_runtime::FailedOutput::logical());
            response.unwrapped_json=Some(crate::auth::UnwrappedJson::from_workflow_output_failure(output));
            return response;
        }
        match output.to_json() {
            Ok(output)=>Response::ok(json!({"data":output})),
            Err(())=>Response::error(500,"workflow output JSON encoding failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: &str = r#"flow "controlled" {
      request "write" { operation = "update" path = "secret/data/cg/workflow"
        data = { data = { value = "after" } } }
    }
    output { data = { marker = "controlled-workflow-completed"
      wrapping = { eval_source = "response" eval_type = "interface{}"
        flow_name = "controlled" response_name = "write" field_selector = ["wrap_info"] } } }"#;
    #[test]
    fn hcl_profile_bounds_sources_and_unknown_expressions_are_checked() {
        let profile = Profile {
            document: PROFILE.into(),
            description: "synthetic".into(),
            cas_required: false,
        };
        let compiled = profile
            .compile()
            .unwrap_or_else(|_| panic!("actual static HCL shape"));
        assert_eq!(compiled.steps.len(), 1);
        assert_eq!(compiled.steps[0].method, "POST");
        assert_eq!(compiled.steps[0].body, json!({"data":{"value":"after"}}));
        let responses = BTreeMap::from([(
            "controlled/write".into(),
            json!({"wrap_info":{"ttl":60,"token":"synthetic"}}),
        )]);
        assert_eq!(
            evaluate_output(&compiled.output, &responses)
                .unwrap_or_else(|_| panic!("response mapping")),
            json!({"marker":"controlled-workflow-completed","wrapping":{"ttl":60,"token":"synthetic"}})
        );
        for text in [
            PROFILE.replace("eval_source = \"response\"", "eval_source = \"cel\""),
            PROFILE.replace("response_name = \"write\"", "response_name = \"missing\""),
            PROFILE.replace("operation = \"update\"", "operation = \"sudo\""),
            PROFILE.replace("data = { data", "unknown = { data"),
            format!("{PROFILE}\noutput {{ data = {{}} }}"),
            format!(
                "flow \"deep\" {{ request \"x\" {{ operation=\"read\" path=\"secret/a\" data={} }} }}",
                "[".repeat(80)
            ),
        ] {
            assert!(
                Profile {
                    document: text,
                    description: String::new(),
                    cas_required: false
                }
                .compile()
                .is_err()
            );
        }
        let mut unknown = serde_json::to_value(profile).expect("encode");
        unknown["extra"] = json!(true);
        assert!(serde_json::from_value::<Profile>(unknown).is_err());
        assert!(
            Profile {
                document: "x".repeat(MAX_PROFILE_BYTES + 1),
                description: String::new(),
                cas_required: false
            }
            .compile()
            .is_err()
        );
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn logical_first_step_fixture(
    profile: &Profile,
    body: &Value,
    started: Instant,
) -> Result<(WorkflowStep, Option<crate::request_metadata::DataFrame>), Response> {
    let program = profile.dynamic_program()?
        .ok_or_else(|| bad_profile("actual dynamic profile required"))?;
    let context = program.context_at(body, started)?;
    let mut resolved = program.steps.first()
        .ok_or_else(|| bad_profile("actual first step required"))?
        .resolve(&context)?
        .ok_or_else(|| bad_profile("actual first step was skipped"))?;
    if resolved.token.is_some() {
        return Err(bad_profile("fixture does not substitute credential admission"));
    }
    let step = WorkflowStep {
        name: std::mem::take(&mut resolved.step.name),
        method: std::mem::take(&mut resolved.step.method),
        path: std::mem::take(&mut resolved.step.path),
        body: std::mem::take(&mut resolved.step.body),
        allow_failure: resolved.step.allow_failure,
    };
    Ok((step, resolved.data_frame.take()))
}

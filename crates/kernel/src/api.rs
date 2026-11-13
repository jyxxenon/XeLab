use crate::{
    admission,
    artifact::Artifact,
    auth::{self, Auth, Context, Resource},
    broker,
    config::Config,
    contracts::{self, id, openapi, strict_json, string, validate},
    db::{self, Db},
    error::{Error, Result},
    identity,
    runtime::Runtime,
    secrets,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use ed25519_dalek::pkcs8::DecodePublicKey;
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub struct App {
    pub config: Config,
    pub db: Db,
    pub auth: Auth,
    pub runtime: Runtime,
    pub leader: Arc<tokio_postgres::Client>,
    pub ready: AtomicBool,
    pub shutdown: AtomicBool,
    pub blob_uploads: tokio::sync::Semaphore,
}
pub fn router(app: Arc<App>) -> Router {
    let compact = app.config.compact();
    let router = Router::new().fallback(handle).with_state(app);
    if compact {
        router.layer(axum::middleware::from_fn_with_state(
            crate::compact_http::Budget::new(),
            crate::compact_http::limit,
        ))
    } else {
        router
    }
}

pub(crate) fn operation(
    method: &str,
    path: &str,
) -> Option<(&'static Value, HashMap<String, String>)> {
    for (template, item) in openapi()["paths"].as_object()? {
        let Some(op) = item.get(method.to_ascii_lowercase()) else {
            continue;
        };
        let a: Vec<_> = template.split('/').collect();
        let b: Vec<_> = path.split('/').collect();
        if a.len() != b.len() {
            continue;
        }
        let mut params = HashMap::new();
        let mut matched = true;
        for (a, b) in a.iter().zip(b) {
            if a.starts_with('{') && a.ends_with('}') {
                params.insert(a[1..a.len() - 1].to_owned(), b.to_owned());
            } else if *a != b {
                matched = false;
                break;
            }
        }
        if matched {
            return Some((op, params));
        }
    }
    None
}
pub(crate) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    if headers.get_all(name).iter().count() != 1 {
        return Err(Error::invalid("Required header must occur exactly once"));
    }
    headers
        .get(name)
        .and_then(|s| s.to_str().ok())
        .ok_or_else(|| Error::invalid("Missing or invalid required header"))
}
pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str> {
    if headers.contains_key("authorization") {
        return header(headers, "authorization")
            .map_err(|_| Error::credential())?
            .strip_prefix("Bearer ")
            .filter(|s| !s.is_empty())
            .ok_or_else(Error::credential);
    }
    let mut found = None;
    for cookie in headers.get_all("cookie") {
        for pair in cookie.to_str().map_err(|_| Error::credential())?.split(';') {
            if let Some(value) = pair.trim().strip_prefix("__Host-xelab_auth=") {
                if found.replace(value).is_some() {
                    return Err(Error::credential());
                }
            }
        }
    }
    found
        .filter(|s| !s.is_empty())
        .ok_or_else(Error::credential)
}
pub(crate) fn path_id(p: &HashMap<String, String>, name: &str) -> Result<Uuid> {
    p.get(name)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::invalid("Invalid path UUID"))
}
pub(crate) fn etag(headers: &HeaderMap, revision: i64) -> Result<()> {
    let value = header(headers, "if-match").map_err(|_| {
        Error::new(
            "PRECONDITION_REQUIRED",
            "If-Match is required",
            StatusCode::PRECONDITION_REQUIRED,
        )
    })?;
    if value != format!("\"rev-{revision}\"") {
        return Err(Error::new(
            "ETAG_MISMATCH",
            "Resource revision changed",
            StatusCode::PRECONDITION_FAILED,
        ));
    }
    Ok(())
}
pub(crate) fn response(value: Value, code: u16, request: Uuid) -> Response {
    let mut r = if code == 204 {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::from_u16(code).unwrap(), Json(value.clone())).into_response()
    };
    r.headers_mut()
        .insert("x-request-id", request.to_string().parse().unwrap());
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    if let Some(rev) = value["revision"].as_i64() {
        r.headers_mut()
            .insert("etag", format!("\"rev-{rev}\"").parse().unwrap());
    }
    r
}
fn trusted_session_token<'a>(operation: Option<&str>, value: &'a Value) -> Option<&'a str> {
    matches!(operation, Some("login" | "activateAccount"))
        .then(|| value.get("access_token").and_then(Value::as_str))
        .flatten()
}

async fn handle(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    let request_id = Uuid::new_v4();
    let response_operation = operation(request.method().as_str(), request.uri().path())
        .and_then(|(operation, _)| operation["operationId"].as_str());
    let host = match crate::plugin_http_gateway::host(&app.config, &request) {
        Ok(host) => host,
        Err(error) => {
            return response(
                json!({"error":error.detail(),"request_id":request_id}),
                error.status.as_u16(),
                request_id,
            )
        }
    };
    if host == crate::plugin_http_gateway::Host::Core
        && crate::oauth_http::handles(request.method().as_str(), request.uri().path())
    {
        return crate::oauth_http::handle(app, peer, request_id, request).await;
    }
    if host != crate::plugin_http_gateway::Host::Core
        || request.uri().path().starts_with("/plugins/")
        || request.uri().path().starts_with("/ui/")
    {
        let headers = request.headers().clone();
        let mut result =
            match crate::plugin_http_gateway::handle(app.clone(), peer, request_id, host, request)
                .await
            {
                Ok(response) => response,
                Err(error) => response(
                    json!({"error":error.detail(),"request_id":request_id}),
                    error.status.as_u16(),
                    request_id,
                ),
            };
        if host == crate::plugin_http_gateway::Host::Core {
            cors_response(&app, &headers, &mut result).await;
        }
        return result;
    }
    // Trusted OAuth pages/native consent have request-bound CSRF semantics;
    // dispatch only after the core Host and before ordinary Cookie CSRF checks.
    if request.uri().path() == "/" && matches!(request.method().as_str(), "GET" | "HEAD") {
        let head = request.method() == axum::http::Method::HEAD;
        let invalid_query = request.uri().query().is_some();
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            to_bytes(request.into_body(), 0),
        )
        .await;
        let boundary = if invalid_query {
            Err(Error::invalid(
                "Root redirect does not accept query parameters",
            ))
        } else {
            match body {
                Ok(Ok(bytes)) if bytes.is_empty() => Ok(()),
                Ok(_) => Err(Error::invalid("Root redirect requires an empty body")),
                Err(_) => Err(Error::unavailable("Root request body deadline elapsed")),
            }
        };
        if let Err(error) = boundary {
            let mut r = response(
                json!({"error":error.detail(),"request_id":request_id}),
                error.status.as_u16(),
                request_id,
            );
            if head {
                *r.body_mut() = Body::empty();
            }
            return r;
        }
        return match crate::webui::redirect(&app).await {
            Ok(location) => Response::builder()
                .status(302)
                .header("location", location)
                .header("cache-control", "no-store")
                .header("x-request-id", request_id.to_string())
                .body(Body::empty())
                .unwrap(),
            Err(error) => {
                let mut r = response(
                    json!({"error":error.detail(),"request_id":request_id}),
                    error.status.as_u16(),
                    request_id,
                );
                if head {
                    *r.body_mut() = Body::empty();
                }
                r
            }
        };
    }
    let headers = request.headers().clone();
    let mut result = handle_core(app.clone(), peer, request_id, request, response_operation).await;
    // CORS conveys no authority. Every foreign request is independently
    // classified/authenticated and authorized before this response is built.
    cors_response(&app, &headers, &mut result).await;
    result
}

async fn cors_response(app: &App, headers: &HeaderMap, result: &mut Response) {
    if crate::oauth_http::request_origin(headers)
        .ok()
        .flatten()
        .is_some_and(|origin| origin != app.config.text("server", "public_origin"))
    {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let c = app
                .db
                .connect_scoped(std::time::Duration::from_secs(3))
                .await?;
            crate::oauth_http::cors_response(&*c, headers, result).await
        })
        .await;
    }
}

// Return before polling the composed operation state so HTTP workers do not
// embed the largest transaction future in every enclosing async frame.
fn handle_core<'a>(
    app: Arc<App>,
    peer: SocketAddr,
    request_id: Uuid,
    request: Request<Body>,
    response_operation: Option<&'a str>,
) -> BoxFuture<'a, Response> {
    Box::pin(async move {
        if !operation(request.method().as_str(), request.uri().path()).is_some_and(|(op, _)| {
            matches!(
                op["operationId"].as_str(),
                Some("getLiveness" | "getReadiness")
            )
        }) {
            let security = if matches!(response_operation, Some("login" | "activateAccount")) {
                crate::plugin_http_gateway::fresh_credential_security(&app, request.headers())
            } else {
                crate::plugin_http_gateway::request_security(
                    &app,
                    peer.ip(),
                    request_id,
                    request.method(),
                    request.headers(),
                )
                .await
            };
            if let Err(error) = security {
                return response(
                    json!({"error":error.detail(),"request_id":request_id}),
                    error.status.as_u16(),
                    request_id,
                );
            }
        }
        if operation(request.method().as_str(), request.uri().path())
            .is_some_and(|(operation, _)| operation["operationId"] == "streamSkill")
        {
            return match crate::skill_streams::handle(app, peer, request_id, request).await {
                Ok(response) => response,
                Err(error) => response(
                    json!({"error":error.detail(),"request_id":request_id}),
                    error.status.as_u16(),
                    request_id,
                ),
            };
        }
        if operation(request.method().as_str(), request.uri().path())
            .is_some_and(|(operation, _)| operation["operationId"] == "streamDeliveries")
        {
            return match crate::event_streams::handle(app, peer, request_id, request).await {
                Ok(value) => value,
                Err(error) => response(
                    json!({"error":error.detail(),"request_id":request_id}),
                    error.status.as_u16(),
                    request_id,
                ),
            };
        }
        let blob = operation(request.method().as_str(), request.uri().path())
            .is_some_and(|(op, _)| crate::blobs::handles(op["operationId"].as_str().unwrap_or("")));
        if blob {
            match crate::blobs::handle(app.clone(), peer, request_id, request).await {
                Ok(response) => return response,
                Err(error) => {
                    return response(
                        json!({"error":error.detail(),"request_id":request_id}),
                        error.status.as_u16(),
                        request_id,
                    )
                }
            }
        }
        match dispatch(&app, peer, request_id, request).await {
            Ok((v, s)) => {
                let token = trusted_session_token(response_operation, &v);
                let csrf = token.map(|token| app.auth.csrf_token(token));
                let cookie=token.map(|token|format!("__Host-xelab_auth={token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600"));
                let mut r = response(v, s, request_id);
                if let Some(cookie) = cookie {
                    r.headers_mut()
                        .insert("set-cookie", cookie.parse().unwrap());
                }
                if let Some(csrf) = csrf {
                    r.headers_mut()
                        .insert("x-csrf-token", csrf.parse().unwrap());
                }
                r
            }
            Err(e) => {
                tracing::warn!(request_id=%request_id,reason_code=e.code,"Request rejected");
                let status = e.status;
                let mut r = response(
                    json!({"error":e.detail(),"request_id":request_id}),
                    status.as_u16(),
                    request_id,
                );
                if e.code == "RATE_LIMITED" {
                    r.headers_mut().insert("retry-after", "60".parse().unwrap());
                }
                r
            }
        }
    })
}

fn dispatch<'a>(
    app: &'a App,
    peer: SocketAddr,
    request_id: Uuid,
    request: Request<Body>,
) -> BoxFuture<'a, Result<(Value, u16)>> {
    Box::pin(async move {
        let (method, uri, headers) = (
            request.method().to_string(),
            request.uri().clone(),
            request.headers().clone(),
        );
        let path = uri.path();
        if path.contains('%') || path.contains("//") {
            return Err(Error::invalid("Noncanonical API path"));
        }
        let (op, params) = operation(&method, path).ok_or_else(Error::not_found)?;
        let name = op["operationId"].as_str().unwrap();
        crate::workflows::validate_query(name, uri.query().unwrap_or(""))?;
        crate::tasks::validate_query(name, uri.query().unwrap_or(""))?;
        if name == "getLiveness" {
            return Ok((
                json!({"status":"ok","spec_version":crate::SPEC_VERSION}),
                200,
            ));
        }
        if name == "getReadiness" {
            if !app.ready.load(Ordering::SeqCst)
                || app.leader.is_closed()
                || app.db.check().await.is_err()
            {
                return Err(Error::unavailable("Kernel reconciliation is incomplete"));
            }
            return Ok((
                json!({"status":"ok","spec_version":crate::SPEC_VERSION}),
                200,
            ));
        }
        let browser_origin = crate::oauth_http::request_origin(&headers)?;
        let maximum = app.config.json_limit(4194304);
        let bytes = to_bytes(request.into_body(), maximum).await.map_err(|_| {
            Error::new(
                "PAYLOAD_TOO_LARGE",
                "Request body exceeds this node's JSON limit",
                StatusCode::PAYLOAD_TOO_LARGE,
            )
        })?;
        let body = if op.get("requestBody").is_some() {
            if header(&headers, "content-type")?.split(';').next() != Some("application/json") {
                return Err(Error::new(
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Expected application/json",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ));
            }
            let value = strict_json(&bytes, maximum)?;
            let model = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                .as_str()
                .and_then(|s| s.rsplit('/').next())
                .ok_or_else(|| Error::invalid("This operation is not supported"))?;
            validate(model, &value)?;
            value
        } else {
            if !bytes.is_empty() {
                return Err(Error::invalid("Unexpected request body"));
            }
            Value::Null
        };
        for parameter in op["parameters"].as_array().unwrap() {
            let source = parameter["in"].as_str().unwrap_or("");
            if source == "header" && parameter["required"] == true {
                let field = parameter["name"].as_str().unwrap();
                if field.eq_ignore_ascii_case("if-match") && !headers.contains_key("if-match") {
                    return Err(Error::new(
                        "PRECONDITION_REQUIRED",
                        "If-Match is required",
                        StatusCode::PRECONDITION_REQUIRED,
                    ));
                }
                let value = header(&headers, field)?;
                contracts::validate_business(&parameter["schema"], &json!(value))?;
            }
        }
        if name == "deleteVolume" {
            crate::volumes::confirm_delete(&params, uri.query().unwrap_or(""))?;
        }
        if name == "activateAccount" {
            let mut c = app.db.connect().await?;
            let tx = c.transaction().await?;
            db::auth_lock(&tx, true).await?;
            let value = identity::activate(&tx, &app.auth, &body, peer.ip(), request_id).await?;
            tx.commit().await?;
            return Ok((value, 200));
        }
        if name == "login" {
            let mut c = app.db.connect().await?;
            let tx = c.transaction().await?;
            db::auth_lock(&tx, false).await?;
            let result = app
                .auth
                .login(
                    &tx,
                    id(&body, "account_id")?,
                    string(&body, "password")?.to_owned(),
                    peer.ip(),
                    request_id,
                )
                .await;
            tx.commit().await?;
            return result.map(|v| (v, 200));
        }
        if app.leader.is_closed() {
            return Err(Error::unavailable("Controller leadership is lost"));
        }
        if !headers.contains_key("authorization")
            && matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
            && headers.get("origin").and_then(|v| v.to_str().ok())
                != Some(app.config.text("server", "public_origin"))
        {
            return Err(Error::denied());
        }
        let token = bearer(&headers)?;
        if name == "invokeCapability" {
            if !app.ready.load(Ordering::SeqCst) {
                return Err(Error::unavailable("Kernel is not ready"));
            }
            return broker::invoke_from_http(
                app,
                token,
                peer.ip(),
                request_id,
                &body,
                header(&headers, "idempotency-key")?,
                None,
                browser_origin,
            )
            .await
            .map(|v| (v, 200));
        }
        if name == "invokeSkill" {
            if !app.ready.load(Ordering::SeqCst) {
                return Err(Error::unavailable("Kernel is not ready"));
            }
            return broker::invoke_from_http(
                app,
                token,
                peer.ip(),
                request_id,
                &body,
                header(&headers, "idempotency-key")?,
                Some(path_id(&params, "skill_id")?),
                browser_origin,
            )
            .await
            .map(|value| (value, 200));
        }
        // QueryResult performs bounded network work between two short authority
        // transactions. Never retain this dispatcher's authorization lock over RPC.
        if name == "getCall" {
            return crate::broker_query::get_call(
                app,
                &headers,
                peer,
                request_id,
                path_id(&params, "call_id")?,
            )
            .await
            .map(|value| (value, 200));
        }
        let mut c = app.db.connect().await?;
        let tx = c.transaction().await?;
        let mutating = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
        db::auth_lock(
            &tx,
            (mutating
                && (identity::handles(name)
                    || secrets::handles(name)
                    || crate::skills::handles(name)
                    || crate::oauth::clients::handles(name)
                    || crate::webui::handles(name)
                    || crate::ui::handles(name)
                    || crate::deployments::handles(name)))
                || matches!(name, "getQuota" | "trustPublisher" | "revokePublisher"),
        )
        .await?;
        let ctx = crate::oauth_http::credential_context(
            &tx,
            &app.auth,
            &headers,
            peer,
            request_id,
            app.config.text("server", "public_origin"),
        )
        .await?;
        if matches!(
            name,
            "resolveDependencies"
                | "createDeployment"
                | "setDeploymentEnabled"
                | "updateDeployment"
                | "upgradeDeployment"
                | "rollbackDeployment"
        ) {
            crate::dependencies::dependency_lock(&tx).await?;
        }
        let key = if mutating {
            Some(header(&headers, "idempotency-key")?)
        } else {
            None
        };
        let canonical = serde_json::to_vec(
            &json!({"body":body,"if_match":headers.get("if-match").and_then(|v|v.to_str().ok())}),
        )?;
        let fingerprint =
            if identity::sensitive(name) || name == "changePassword" || secrets::writes_value(name)
            {
                contracts::digest(
                    &app.auth.token_digest(
                        std::str::from_utf8(&canonical)
                            .map_err(|_| Error::invalid("Invalid fingerprint"))?,
                    ),
                )
            } else {
                contracts::digest(&canonical)
            };
        if let Some(key) = key {
            let lock = format!("{}:{}:{method}:{path}:{key}", ctx.subject, ctx.credential);
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock],
            )
            .await?;
            if let Some(row)=tx.query_opt("SELECT fingerprint,safe_response,response_status,sensitive,resource_id FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method=$3 AND path=$4 AND key=$5 AND expires_at>now()",&[&ctx.subject,&ctx.credential,&method,&path,&key]).await?{
            let task_recovery = matches!(name, "resolveUnknownStep" | "cancelTask");
            if task_recovery {
                // A stale Task grant must not reveal whether a previously
                // submitted idempotency key or fingerprint exists.
                authorize_operation(&tx, &app.auth, &ctx, name, &params, &body).await?;
            }
            if row.get::<_,String>("fingerprint")!=fingerprint{return Err(Error::new("IDEMPOTENCY_CONFLICT","Idempotency key fingerprint differs",StatusCode::CONFLICT));}
            if row.get::<_,bool>("sensitive") {
                authorize_operation(&tx,&app.auth,&ctx,name,&params,&body).await?;
                return Err(Error::new("ONE_TIME_RESPONSE_UNAVAILABLE","The one-time secret is unavailable; inspect the existing resource",StatusCode::CONFLICT).with_resource(row.get::<_,String>("resource_id")));
            }
            // Authentication has been rechecked; resource authorization is checked by the same dispatch before any replay below.
            let response: Option<Value> = row.get("safe_response");
            if let Some(value) = response {
                if name == "trustPublisher" && row.get::<_,i32>("response_status") == 201 {
                    auth::authorize(&tx, &ctx, "publisher.trust", &Resource::new("publisher", "new", Some(ctx.subject))).await?;
                } else if !task_recovery {
                    authorize_operation(&tx, &app.auth, &ctx, name, &params, &body).await?;
                }
                if matches!(name, "upgradeDeployment" | "rollbackDeployment") {
                    crate::upgrades::authorize_replay(&tx, &ctx, id(&value, "id")?).await?;
                }
                if matches!(name,"setDeploymentEnabled"|"upgradeDeployment"|"rollbackDeployment") {
                    crate::schema_jobs::authorize_replay(&tx, &ctx, id(&value, "id")?).await?;
                }
                return Ok((value, row.get::<_,i32>("response_status") as u16));
            }
            return Err(Error::conflict("Operation has no replayable response"));
        }
        }
        if let Err(error) = authorize_operation(&tx, &app.auth, &ctx, name, &params, &body).await {
            db::audit(
                &tx,
                ctx.subject,
                Some(ctx.credential),
                request_id,
                name,
                &operation_audit_resource(
                    &tx,
                    name,
                    &params,
                    ctx.subject,
                    &Value::Null,
                    error.code != "PERMISSION_DENIED",
                )
                .await?,
                "denied",
                error.code,
            )
            .await?;
            tx.commit().await?;
            return Err(error);
        }
        tx.batch_execute("SAVEPOINT mutation").await?;
        let execution=async {
    let result = if identity::handles(name) {
        identity::execute(&tx,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::events::handles(name) {
        crate::events::execute(&tx,app,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::plugin_catalog::handles(name) {
        crate::plugin_catalog::execute(&tx,&app.auth,&ctx,name,uri.query().unwrap_or("")).await?
    } else if crate::oauth::clients::handles(name) {
        crate::oauth::clients::execute(&tx,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::webui::handles(name) {
        crate::webui::execute(&tx,app,&ctx,name,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::ui::handles(name) {
        crate::ui::execute(&tx,app,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::deployments::handles(name) {
        crate::deployments::execute(&tx,app,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::skills::handles(name) {
        crate::skills::execute(&tx,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::workflows::handles(name) {
        crate::workflows::execute(&tx,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::tasks::handles(name) {
        crate::tasks::execute(&tx,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else if crate::volumes::handles(name) {
        crate::volumes::execute(&tx,app,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("" )).await?
    } else if crate::backups::handles(name) {
        crate::backups::execute(&tx,app,&ctx,name,&params,&body,uri.query().unwrap_or("")).await?
    } else if secrets::handles(name) {
        secrets::execute(&tx,&app.config,&app.auth,&ctx,name,&params,&body,&headers,uri.query().unwrap_or("")).await?
    } else {match name {
        "upgradeDeployment" | "rollbackDeployment" => {
            let action=if name=="upgradeDeployment"{"plugin.upgrade"}else{"plugin.rollback"};
            crate::upgrades::create(&tx,app,&ctx,path_id(&params,"deployment_id")?,action,&body,&headers).await?
        }
        "cancelCall" => {
            let call = path_id(&params, "call_id")?;
            db::call_lock(&tx).await?;
            authorize_operation(&tx, &app.auth, &ctx, name, &params, &body).await?;
            crate::broker::request_cancellation(&tx, &[call]).await?;
            (Value::Null, 204)
        }
        "getNode" => (admission::status(&tx).await?, 200),
        "getOperation" => (
            db::operation_value(&tx, path_id(&params, "operation_id")?).await?,
            200,
        ),
        "trustPublisher" => {
            let submitted = ed25519_dalek::VerifyingKey::from_public_key_pem(string(&body, "public_key_pem")?)
                .map_err(|_| Error::invalid("Expected an Ed25519 public key"))?;
            let (publisher, status) = if let Some(existing) = tx.query_opt("SELECT * FROM publishers WHERE key_id=$1 FOR UPDATE", &[&string(&body,"key_id")?]).await? {
                let registered = ed25519_dalek::VerifyingKey::from_public_key_pem(&existing.get::<_,String>("public_key_pem"))
                    .map_err(|_| Error::conflict("Registered publisher key is invalid"))?;
                if registered != submitted || existing.get::<_,String>("name") != string(&body,"name")? {
                    return Err(Error::conflict("Existing publisher identity or key differs; key rotation requires a new key_id"));
                }
                let publisher: Uuid = existing.get("id");
                if existing.get::<_,String>("status") == "revoked" {
                    tx.execute("UPDATE publishers SET status='trusted',revision=revision+1,updated_at=now() WHERE id=$1", &[&publisher]).await?;
                }
                (publisher, 200)
            } else {
                let publisher = Uuid::new_v4();
                tx.execute("INSERT INTO publishers(id,name,key_id,public_key_pem,status,created_at,updated_at) VALUES($1,$2,$3,$4,'trusted',now(),now())",&[&publisher,&string(&body,"name")?,&string(&body,"key_id")?,&string(&body,"public_key_pem")?]).await?;
                (publisher, 201)
            };
            (read_object(&tx, "publishers", publisher, "Publisher").await?, status)
        }
        "installPlugin" => {
            let publisher = id(&body, "publisher_id")?;
            if tx
                .query_opt(
                    "SELECT id FROM publishers WHERE id=$1 AND status='trusted' FOR SHARE",
                    &[&publisher],
                )
                .await?
                .is_none()
            {
                return Err(Error::denied());
            }
            let id = db::operation(&tx, ctx.subject, name, None).await?;
            db::outbox(
                &tx,
                "kernel.install",
                id,
                &json!({"request":body,"credential_id":ctx.credential,"subject_id":ctx.subject,"peer":peer.ip().to_string()}),
            )
            .await?;
            (db::operation_value(&tx, id).await?, 202)
        }
        "resolveDependencies" => (crate::dependencies::plan(&tx,&ctx,id(&body,"deployment_id")?,id(&body,"installation_id")?).await?,200),
        "createDeployment" => {
            if body["enabled"] == true {
                return Err(Error::invalid(
                    "Create a disabled deployment, approve it, then enable it",
                ));
            }
            let installation = id(&body, "installation_id")?;
            let r = tx
                .query_opt(
                    "SELECT * FROM installations WHERE id=$1 AND state='installed' FOR SHARE",
                    &[&installation],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            let artifact = Artifact {
                image: String::new(),
                manifest: r.get("manifest"),
                raw: Vec::new(),
                image_digest: r.get("image_digest"),
                manifest_digest: r.get("manifest_digest"),
                http_contract: None,
            };
            artifact.validate_deployment(&body)?;
            crate::http_contracts::validate_actions(&tx,&artifact.manifest).await?;
            crate::volumes::validate_selection(&tx,&ctx,&body,&artifact.manifest).await?;
            let mut spec = body.clone();
            spec["enabled"] = json!(false);
            if spec.get("replicas").is_none() {
                spec["replicas"] = json!(1);
            }
            let id = Uuid::new_v4();
            tx.execute("INSERT INTO deployments(id,owner_id,installation_id,spec,phase,created_at,updated_at) VALUES($1,$2,$3,$4,'disabled',now(),now())",&[&id,&ctx.subject,&installation,&spec]).await?;
            let op = db::operation(&tx, ctx.subject, name, Some(id.to_string())).await?;
            let deployment = read_object(&tx, "deployments", id, "Deployment").await?;
            db::complete(&tx, op, Ok(deployment)).await?;
            (db::operation_value(&tx, op).await?, 202)
        }
        "approvePlugin" => {
            let id = path_id(&params, "deployment_id")?;
            let r = tx
                .query_one(
                    "SELECT spec,revision,owner_id,installation_id FROM deployments WHERE id=$1 FOR UPDATE",
                    &[&id],
                )
                .await?;
            crate::backups::ensure_unheld(&tx,id).await?;
            etag(&headers, r.get("revision"))?;
            if r.get::<_, Value>("spec")["enabled"] == true {
                return Err(Error::conflict(
                    "Approval changes require a disabled deployment",
                ));
            }
            let manifest:Value=tx.query_one("SELECT manifest FROM installations WHERE id=$1",&[&r.get::<_,Uuid>("installation_id")]).await?.get(0);
            crate::http_contracts::validate_actions(&tx,&manifest).await?;
            crate::host_blobs::approve(&tx,&ctx,id,&manifest,&body,r.get("owner_id")).await?;
            crate::plugin_http_gateway::approve(&tx,&ctx,id,&manifest,&body,r.get("owner_id")).await?;
            tx.execute("UPDATE deployments SET approval=$2,revision=revision+1,updated_at=now() WHERE id=$1",&[&id,&body]).await?;
            (body.clone(), 200)
        }
        "setDeploymentEnabled" => {
            let id = path_id(&params, "deployment_id")?;
            let bootstrap = if body["enabled"] == true {
                crate::schema_jobs::preflight(&tx,app,&ctx,id).await?
            } else { None };
            let bootstrapping = bootstrap.is_some();
            tx.query_one("SELECT id FROM node_budget FOR UPDATE",&[]).await?;
            let row = tx
                .query_one("SELECT * FROM deployments WHERE id=$1 FOR UPDATE", &[&id])
                .await?;
            crate::backups::ensure_unheld(&tx,id).await?;
            etag(&headers, row.get("revision"))?;
            tx.execute("UPDATE operations SET state='failed',error=$2,revision=revision+1,updated_at=now() WHERE resource_id=$1 AND kind='setDeploymentEnabled' AND state IN ('pending','running')", &[&id.to_string(),&Error::conflict("Superseded by a newer deployment intent").detail()]).await?;
            let enabled = body["enabled"].as_bool().unwrap();
            let mut spec: Value = row.get("spec");
            if enabled {
                let manifest:Value=tx.query_one("SELECT manifest FROM installations WHERE id=$1",&[&row.get::<_,Uuid>("installation_id")]).await?.get(0);
                crate::http_contracts::validate_actions(&tx,&manifest).await?;
                crate::host_blobs::check_approval(&tx,app,id,&manifest).await?;
                // Gateway readiness validates the fixed dependency graph.
                // Bind after Host approval in this same transaction so a later
                // denial rolls back both bindings and the enable intent.
                if spec["enabled"] != true {
                    crate::dependencies::bind(&tx,app,&ctx,id).await?;
                }
                crate::plugin_http_gateway::check_approval(&tx,app,id,&manifest).await?;
            }
            if bootstrap.is_some() && (!enabled || spec["enabled"] == true) {
                return Err(Error::conflict("Schema bootstrap intent changed during preflight"));
            }
            let op = db::operation(&tx, ctx.subject, name, Some(id.to_string())).await?;
            if enabled && spec["enabled"] != true {
                if tx.query_one("SELECT count(*) FROM instances WHERE deployment_id=$1 AND phase<>'stopped'",&[&id]).await?.get::<_,i64>(0)>0{return Err(Error::conflict("Previous instances have not drained"));}
                let instance = Uuid::new_v4();
                let generation = row.get::<_, i64>("revision") + 1;
                let manifest:Value=tx.query_one("SELECT manifest FROM installations WHERE id=$1",&[&row.get::<_,Uuid>("installation_id")]).await?.get(0);
                crate::volumes::approve_mounts(&tx,&ctx,id,generation,&spec,&manifest).await?;
                tx.execute("INSERT INTO instances(id,deployment_id,generation,ordinal,phase,health,limits,created_at,updated_at) VALUES($1,$2,$3,0,'pending','unknown',$4,now(),now())",&[&instance,&id,&generation,&spec["limits"]]).await?;
                if let Some(admitted) = bootstrap {
                    crate::schema_jobs::reserve(&tx,&ctx,id,op,instance,generation,admitted).await?;
                }
            }
            spec["enabled"] = json!(enabled);
            let phase = if enabled { "reconciling" } else { "draining" };
            tx.execute("UPDATE deployments SET spec=$2,phase=$3,revision=revision+1,updated_at=now() WHERE id=$1",&[&id,&spec,&phase]).await?;
            if bootstrapping {
                let admitted = tx.query_one("SELECT j.*,host(j.peer) AS approved_peer FROM volume_schema_jobs j WHERE operation_id=$1", &[&op]).await?;
                // The same budget transaction first publishes the enabled
                // intent; reserve() rejects an instance of a disabled intent.
                crate::admission::reserve(&tx,admitted.get("instance_id")).await?;
                crate::schema_jobs::revalidate(&tx,app,&admitted).await?;
            }
            if !enabled {
                crate::dependencies::invalidate_dependents(&tx,id).await?;
                crate::dependencies::clear(&tx,id).await?;
                tx.execute("UPDATE provider_records SET availability='unavailable' WHERE instance_id IN(SELECT id FROM instances WHERE deployment_id=$1)",&[&id]).await?;
            }
            db::outbox(&tx, "deployment.changed", id, &json!({})).await?;
            (db::operation_value(&tx, op).await?, 202)
        }
        "getInstallation" => (
            read_object(
                &tx,
                "installations",
                path_id(&params, "installation_id")?,
                "Installation",
            )
            .await?,
            200,
        ),
        "getDeployment" => (
            read_object(
                &tx,
                "deployments",
                path_id(&params, "deployment_id")?,
                "Deployment",
            )
            .await?,
            200,
        ),
        "getInstance" => (
            read_object(
                &tx,
                "instances",
                path_id(&params, "instance_id")?,
                "Instance",
            )
            .await?,
            200,
        ),
        "getPublisher" => (
            read_object(
                &tx,
                "publishers",
                path_id(&params, "publisher_id")?,
                "Publisher",
            )
            .await?,
            200,
        ),
        "getPluginApproval" => {
            let row = tx
                .query_one(
                    "SELECT approval FROM deployments WHERE id=$1",
                    &[&path_id(&params, "deployment_id")?],
                )
                .await?;
            let approval: Value = row.get(0);
            if approval == json!({}) {
                return Err(Error::unavailable("Deployment has not been approved"));
            }
            (approval, 200)
        }
        "revokePublisher" => {
            let id = path_id(&params, "publisher_id")?;
            let row = tx
                .query_one(
                    "SELECT revision FROM publishers WHERE id=$1 FOR UPDATE",
                    &[&id],
                )
                .await?;
            etag(&headers, row.get(0))?;
            tx.execute("UPDATE publishers SET status='revoked',revision=revision+1,updated_at=now() WHERE id=$1",&[&id]).await?;
            (Value::Null, 204)
        }
        "revokeSession" => {
            let id = path_id(&params, "session_id")?;
            let row = tx
                .query_one(
                    "SELECT revision FROM credentials WHERE id=$1 AND kind='session' FOR UPDATE",
                    &[&id],
                )
                .await?;
            etag(&headers, row.get(0))?;
            tx.execute("UPDATE credentials SET status='revoked',revision=revision+1,updated_at=now() WHERE id=$1",&[&id]).await?;
            (Value::Null, 204)
        }
        _ => {
            return Err(Error::unavailable(
                "Operation is not implemented in the M1 profile; see crates/kernel/README.md",
            ))
        }
    }
    };
    Ok::<_,Error>(result)
    }.await;
        let result = match execution {
            Ok(value) => value,
            Err(e) => {
                tx.batch_execute("ROLLBACK TO SAVEPOINT mutation").await?;
                db::audit(
                    &tx,
                    ctx.subject,
                    Some(ctx.credential),
                    request_id,
                    name,
                    &operation_audit_resource(
                        &tx,
                        name,
                        &params,
                        ctx.subject,
                        &Value::Null,
                        matches!(e.code, "RESOURCE_NOT_FOUND" | "INVALID_CREDENTIAL"),
                    )
                    .await?,
                    "failed",
                    e.code,
                )
                .await?;
                tx.commit().await?;
                return Err(e);
            }
        };
        if mutating {
            db::audit(
                &tx,
                ctx.subject,
                Some(ctx.credential),
                request_id,
                name,
                &operation_audit_resource(&tx, name, &params, ctx.subject, &result.0, false)
                    .await?,
                "succeeded",
                "COMMITTED",
            )
            .await?;
            let key = key.unwrap();
            tx.execute("DELETE FROM idempotency_records WHERE subject_id=$1 AND credential_id=$2 AND method=$3 AND path=$4 AND key=$5 AND expires_at<=now()",&[&ctx.subject,&ctx.credential,&method,&path,&key]).await?;
            let sensitive = identity::sensitive(name);
            let resource = if name == "createChildAccount" {
                result.0["account"]["id"].as_str()
            } else {
                result.0["credential"]["id"].as_str()
            }
            .map(str::to_owned);
            let safe = if sensitive {
                None
            } else {
                Some(result.0.clone())
            };
            tx.execute("INSERT INTO idempotency_records(subject_id,credential_id,method,path,key,fingerprint,response_status,safe_response,sensitive,resource_id,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+interval '24 hours',now())",&[&ctx.subject,&ctx.credential,&method,&path,&key,&fingerprint,&(result.1 as i32),&safe,&sensitive,&resource]).await?;
        }
        if let Some(model) = op["responses"][result.1.to_string()]["content"]["application/json"]
            ["schema"]["$ref"]
            .as_str()
            .and_then(|r| r.rsplit('/').next())
        {
            validate(model, &result.0)?;
        }
        if app.leader.is_closed() {
            return Err(Error::unavailable("Controller leadership is lost"));
        }
        tx.commit().await?;
        Ok(result)
    })
}

async fn operation_audit_resource(
    c: &(impl GenericClient + Sync),
    name: &str,
    params: &HashMap<String, String>,
    subject: Uuid,
    response: &Value,
    concealed: bool,
) -> Result<Value> {
    let fallback = || identity::audit_resource(name, params, subject, response);
    if name == "resolveUnknownStep" && !concealed {
        let Ok(step) = path_id(params, "step_id") else {
            return Ok(fallback());
        };
        return Ok(crate::tasks::step_task_resource(c, step)
            .await?
            .map_or_else(fallback, |resource| resource.json()));
    }
    Ok(fallback())
}

async fn authorize_operation(
    c: &(impl GenericClient + Sync),
    app_auth: &Auth,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    body: &Value,
) -> Result<()> {
    if identity::handles(name) {
        return identity::authorize(c, ctx, name, params, body).await;
    }
    if crate::events::handles(name) {
        return crate::events::authorize(c, app_auth, ctx, name, params, body).await;
    }
    if crate::plugin_catalog::handles(name) {
        // Collection entry grants no object authority. The catalog filters each
        // object using the current credential/Origin policy and actual owner.
        return Ok(());
    }
    if crate::oauth::clients::handles(name) {
        return crate::oauth::clients::authorize(c, ctx, name, params, body).await;
    }
    if crate::webui::handles(name) {
        return crate::webui::authorize(c, ctx, name).await;
    }
    if crate::ui::handles(name) {
        return crate::ui::authorize(c, ctx, name, params, body).await;
    }
    if crate::deployments::handles(name) {
        return crate::deployments::authorize(c, ctx, name, params, body).await;
    }
    if crate::skills::handles(name) {
        return crate::skills::authorize(c, ctx, name, params, body).await;
    }
    if crate::workflows::handles(name) {
        return crate::workflows::authorize(c, ctx, name, params).await;
    }
    if crate::tasks::handles(name) {
        return crate::tasks::authorize(c, ctx, name, params, body).await;
    }
    if secrets::handles(name) {
        return secrets::authorize(c, ctx, name, params, body).await;
    }
    if crate::volumes::handles(name) {
        return crate::volumes::authorize(c, ctx, name, params).await;
    }
    if crate::backups::handles(name) {
        return crate::backups::authorize(c, ctx, name, params, body).await;
    }
    if matches!(name, "upgradeDeployment" | "rollbackDeployment") {
        let action = if name == "upgradeDeployment" {
            "plugin.upgrade"
        } else {
            "plugin.rollback"
        };
        return crate::upgrades::authorize(c, ctx, path_id(params, "deployment_id")?, action, body)
            .await;
    }
    if name == "installPlugin" {
        // Stage/verify the signed artifact first. Only its verified manifest can
        // supply plugin_id; the worker authorizes that actual ID before commit.
        let paths = crate::policy::Policy::for_context(c, ctx)
            .credential(ctx.credential, 0)
            .await?;
        if paths.iter().any(|p| {
            p.rule["action"] == "plugin.install"
                && p.rule["resource"]["kind"] == "plugin"
                && p.rule
                    .get("conditions")
                    .is_none_or(|v| auth::conditions_match(v, ctx.peer, chrono::Utc::now()))
        }) {
            return Ok(());
        }
        return Err(Error::denied());
    }
    let (action, resource) = match name {
        "getCall" | "cancelCall" => {
            let id = path_id(params, "call_id")?;
            let r = c
                .query_opt("SELECT owner_id FROM calls WHERE id=$1", &[&id])
                .await?
                .ok_or_else(Error::not_found)?;
            (
                if name == "cancelCall" {
                    "capability.call.cancel"
                } else {
                    "capability.call.read"
                },
                Resource::new("call", id, Some(r.get(0))),
            )
        }
        "getNode" => ("platform.read", Resource::new("platform", "node", None)),
        "trustPublisher" => {
            let existing = c
                .query_opt(
                    "SELECT id FROM publishers WHERE key_id=$1",
                    &[&string(body, "key_id")?],
                )
                .await?;
            (
                "publisher.trust",
                existing.map_or_else(
                    || Resource::new("publisher", "new", Some(ctx.subject)),
                    |row| Resource::new("publisher", row.get::<_, Uuid>(0), None),
                ),
            )
        }
        "installPlugin" => (
            "plugin.install",
            Resource::new(
                "plugin",
                body["image"].as_str().unwrap_or(""),
                Some(ctx.subject),
            ),
        ),
        "createDeployment" => (
            "plugin.deploy",
            Resource::new("deployment", "new", Some(ctx.subject)),
        ),
        "getPublisher" | "revokePublisher" => {
            let id = path_id(params, "publisher_id")?;
            if c.query_opt("SELECT id FROM publishers WHERE id=$1", &[&id])
                .await?
                .is_none()
            {
                return Err(Error::not_found());
            }
            (
                if name == "getPublisher" {
                    "publisher.read"
                } else {
                    "publisher.revoke"
                },
                Resource::new("publisher", id, None),
            )
        }
        "getInstallation" => {
            let id = path_id(params, "installation_id")?;
            let r = c
                .query_opt("SELECT plugin_id FROM installations WHERE id=$1", &[&id])
                .await?
                .ok_or_else(Error::not_found)?;
            (
                "plugin.read",
                Resource::new("plugin", r.get::<_, String>(0), None),
            )
        }
        "resolveDependencies" => {
            let id = id(body, "deployment_id")?;
            let row = c
                .query_opt(
                    "SELECT owner_id FROM deployments WHERE id=$1 AND archived_at IS NULL",
                    &[&id],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            (
                "plugin.dependencies.read",
                Resource::new("deployment", id, Some(row.get(0))),
            )
        }
        "getDeployment" | "setDeploymentEnabled" | "approvePlugin" | "getPluginApproval" => {
            let id = path_id(params, "deployment_id")?;
            let r = c
                .query_opt("SELECT owner_id FROM deployments WHERE id=$1", &[&id])
                .await?
                .ok_or_else(Error::not_found)?;
            (
                match name {
                    "setDeploymentEnabled" => "plugin.enable",
                    "approvePlugin" => "plugin.permission.grant",
                    _ => "plugin.read",
                },
                Resource::new("deployment", id, Some(r.get(0))),
            )
        }
        "getInstance" => {
            let id = path_id(params, "instance_id")?;
            let r=c.query_opt("SELECT d.owner_id FROM instances i JOIN deployments d ON d.id=i.deployment_id WHERE i.id=$1",&[&id]).await?.ok_or_else(Error::not_found)?;
            ("plugin.read", Resource::new("instance", id, Some(r.get(0))))
        }
        "getOperation" => {
            let id = path_id(params, "operation_id")?;
            let r = c
                .query_opt("SELECT owner_id FROM operations WHERE id=$1", &[&id])
                .await?
                .ok_or_else(Error::not_found)?;
            (
                "operation.read",
                Resource::new("operation", id, Some(r.get(0))),
            )
        }
        "revokeSession" => {
            let id = path_id(params, "session_id")?;
            let r = c
                .query_opt(
                    "SELECT owner_id FROM credentials WHERE id=$1 AND kind='session'",
                    &[&id],
                )
                .await?
                .ok_or_else(Error::not_found)?;
            let owner: Uuid = r.get(0);
            if owner != ctx.subject {
                return Err(Error::not_found());
            }
            (
                "session.revoke",
                Resource::new("credential", id, Some(owner)),
            )
        }
        _ => {
            return Err(Error::unavailable(
                "Operation is not implemented in the M1 profile; see crates/kernel/README.md",
            ))
        }
    };
    auth::authorize(c, ctx, action, &resource)
        .await
        .map_err(|e| {
            if name.starts_with("get") && e.code == "PERMISSION_DENIED" {
                Error::not_found()
            } else {
                e
            }
        })
}

pub(crate) async fn read_object(
    c: &(impl GenericClient + Sync),
    table: &str,
    id: Uuid,
    model: &str,
) -> Result<Value> {
    // table is selected exclusively from the static dispatch above.
    let row = c
        .query_opt(
            &format!("SELECT to_jsonb(t) FROM {table} t WHERE id=$1"),
            &[&id],
        )
        .await?
        .ok_or_else(Error::not_found)?;
    let raw: Value = row.get(0);
    object_value(&raw, model)
}

pub(crate) fn object_value(raw: &Value, model: &str) -> Result<Value> {
    let mut result = json!({});
    for key in openapi()["components"]["schemas"][model]["required"]
        .as_array()
        .unwrap()
    {
        let key = key.as_str().unwrap();
        result[key] = raw[key].clone();
    }
    validate(model, &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_trusted_session_operations_can_issue_login_cookie() {
        let value = json!({"access_token":"plugin-or-oauth-output"});
        assert_eq!(
            trusted_session_token(Some("login"), &value),
            Some("plugin-or-oauth-output")
        );
        for operation in [
            None,
            Some("invokeCapability"),
            Some("invokeSkill"),
            Some("exchangeOAuthToken"),
            Some("getCall"),
            Some("createClient"),
        ] {
            assert!(trusted_session_token(operation, &value).is_none());
        }
        assert!(trusted_session_token(
            Some("login"),
            &json!({"output":{"access_token":"nested-plugin-output"}})
        )
        .is_none());
    }
    #[test]
    fn paths_match_only_existing_operations() {
        assert_eq!(
            operation("GET", "/health/live").unwrap().0["operationId"],
            "getLiveness"
        );
        assert!(operation("POST", "/health/live").is_none());
        assert!(operation("GET", "/made-up").is_none());
        assert_eq!(
            operation("PUT", "/api/platform/v1/deployments/x/enabled")
                .unwrap()
                .1["deployment_id"],
            "x"
        );
    }
}

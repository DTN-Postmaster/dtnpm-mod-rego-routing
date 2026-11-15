//! Axum REST API handlers for managing blacklisted EIDs, active OPA/Rego policies,
//! and viewing the Rego policy decision audit log.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dtnpm_web_core::ModuleContext;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

use crate::engine::{
    BlacklistEntry, DecisionAuditEntry, RegoRoutingConfig, RegoRoutingEngine, validate_eid_pattern,
};
use crate::policy::PolicySources;

/// Shared Axum router state pairing DTN Postmaster's [`ModuleContext`]
/// with the live [`RegoRoutingEngine`] used by Hardy's BPA filters.
#[derive(Clone)]
pub struct RegoRouteState {
    pub ctx: ModuleContext,
    pub engine: Arc<RegoRoutingEngine>,
}

/// Request payload for `POST /blacklist`.
#[derive(Debug, Deserialize)]
pub struct CreateBlacklistRequest {
    pub eid_pattern: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Request payload for `PATCH /blacklist/{id}`.
#[derive(Debug, Deserialize)]
pub struct ToggleBlacklistRequest {
    pub enabled: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request payload for `PUT /policy`.
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub active_profile: Option<String>,
    pub hop_limit: Option<u8>,
    pub treb_block_type: Option<u64>,
    pub custom_ingress_rego: Option<String>,
    pub custom_egress_rego: Option<String>,
    #[serde(default)]
    pub reset_to_default: bool,
}

/// Response payload for `GET /policy` and `PUT /policy`.
#[derive(Debug, Serialize)]
pub struct PolicyStatusResponse {
    pub config: RegoRoutingConfig,
    pub sources: PolicySources,
}

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err_response(status: StatusCode, msg: impl std::fmt::Display) -> ApiErr {
    (status, Json(json!({ "error": msg.to_string() })))
}

/// `GET /blacklist` - Returns all configured EID blacklist patterns.
pub async fn list_blacklist(
    State(state): State<RegoRouteState>,
) -> Result<Json<Vec<BlacklistEntry>>, ApiErr> {
    let conn_lock = state.ctx.internal_storage.connection();
    let conn = conn_lock
        .lock()
        .map_err(|_| err_response(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned"))?;

    let mut stmt = conn
        .prepare(
            "SELECT id, eid_pattern, reason, enabled, created_at, created_by
             FROM rego_blacklist ORDER BY created_at DESC, eid_pattern ASC",
        )
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let rows = stmt
        .query_map([], |row| {
            let enabled_i: i64 = row.get(3)?;
            Ok(BlacklistEntry {
                id: row.get(0)?,
                eid_pattern: row.get(1)?,
                reason: row.get(2)?,
                enabled: enabled_i != 0,
                created_at: row.get(4)?,
                created_by: row.get(5)?,
            })
        })
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let mut entries = Vec::new();
    for r in rows {
        entries.push(r.map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?);
    }
    Ok(Json(entries))
}

/// `POST /blacklist` - Validates and persists a new source EID blacklist rule.
pub async fn create_blacklist(
    State(state): State<RegoRouteState>,
    Json(payload): Json<CreateBlacklistRequest>,
) -> Result<(StatusCode, Json<BlacklistEntry>), ApiErr> {
    let normalized = validate_eid_pattern(&payload.eid_pattern)
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;
    let reason = payload.reason.trim();
    if reason.len() > 512 {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "reason exceeds 512 character limit",
        ));
    }

    let now_ts = OffsetDateTime::now_utc().unix_timestamp();
    let id = format!("bl-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
    let entry = BlacklistEntry {
        id,
        eid_pattern: normalized,
        reason: reason.to_string(),
        enabled: payload.enabled,
        created_at: now_ts,
        created_by: "webui".to_string(),
    };

    {
        let conn_lock = state.ctx.internal_storage.connection();
        let conn = conn_lock.lock().map_err(|_| {
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned")
        })?;

        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM rego_blacklist WHERE eid_pattern = ?1",
                rusqlite::params![&entry.eid_pattern],
                |row| row.get(0),
            )
            .ok();
        if existing.is_some() {
            return Err(err_response(
                StatusCode::CONFLICT,
                "EID pattern is already blacklisted",
            ));
        }

        conn.execute(
            "INSERT INTO rego_blacklist (id, eid_pattern, reason, enabled, created_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &entry.id,
                &entry.eid_pattern,
                &entry.reason,
                i64::from(entry.enabled),
                entry.created_at,
                &entry.created_by,
            ],
        )
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    state.engine.upsert_blacklist_entry(entry.clone());
    Ok((StatusCode::CREATED, Json(entry)))
}

/// `DELETE /blacklist/{id}` - Deletes a blacklist rule by ID.
pub async fn delete_blacklist(
    State(state): State<RegoRouteState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiErr> {
    let deleted = {
        let conn_lock = state.ctx.internal_storage.connection();
        let conn = conn_lock.lock().map_err(|_| {
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned")
        })?;

        conn.execute(
            "DELETE FROM rego_blacklist WHERE id = ?1",
            rusqlite::params![&id],
        )
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    if deleted == 0 {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "Blacklist entry not found",
        ));
    }
    state.engine.remove_blacklist_entry(&id);
    Ok(StatusCode::NO_CONTENT)
}

/// `PATCH /blacklist/{id}` - Enables/disables an existing blacklist rule.
pub async fn toggle_blacklist(
    State(state): State<RegoRouteState>,
    Path(id): Path<String>,
    Json(payload): Json<ToggleBlacklistRequest>,
) -> Result<Json<BlacklistEntry>, ApiErr> {
    if let Some(reason) = &payload.reason
        && reason.len() > 512
    {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "reason exceeds 512 character limit",
        ));
    }

    let updated = {
        let conn_lock = state.ctx.internal_storage.connection();
        let conn = conn_lock.lock().map_err(|_| {
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned")
        })?;

        let rows_affected = if let Some(reason) = &payload.reason {
            conn.execute(
                "UPDATE rego_blacklist SET enabled = ?1, reason = ?2 WHERE id = ?3",
                rusqlite::params![i64::from(payload.enabled), reason.trim(), &id],
            )
        } else {
            conn.execute(
                "UPDATE rego_blacklist SET enabled = ?1 WHERE id = ?2",
                rusqlite::params![i64::from(payload.enabled), &id],
            )
        }
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        if rows_affected == 0 {
            return Err(err_response(
                StatusCode::NOT_FOUND,
                "Blacklist entry not found",
            ));
        }

        conn.query_row(
            "SELECT id, eid_pattern, reason, enabled, created_at, created_by
             FROM rego_blacklist WHERE id = ?1",
            rusqlite::params![&id],
            |row| {
                let enabled_i: i64 = row.get(3)?;
                Ok(BlacklistEntry {
                    id: row.get(0)?,
                    eid_pattern: row.get(1)?,
                    reason: row.get(2)?,
                    enabled: enabled_i != 0,
                    created_at: row.get(4)?,
                    created_by: row.get(5)?,
                })
            },
        )
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    state.engine.upsert_blacklist_entry(updated.clone());
    Ok(Json(updated))
}

/// `GET /policy` - Returns current Rego policy configuration and source texts.
pub async fn get_policy(State(state): State<RegoRouteState>) -> Json<PolicyStatusResponse> {
    Json(PolicyStatusResponse {
        config: state.engine.config(),
        sources: state.engine.policy_sources(),
    })
}

/// `PUT /policy` - Validates, compiles, persists, and hot-reloads active Rego policies.
pub async fn update_policy(
    State(state): State<RegoRouteState>,
    Json(payload): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyStatusResponse>, ApiErr> {
    let current = state.engine.config();

    let (active_profile, custom_ingress, custom_egress) = if payload.reset_to_default {
        ("default".to_string(), None, None)
    } else {
        let ingress = payload
            .custom_ingress_rego
            .or(current.custom_ingress_rego.clone())
            .filter(|s| !s.trim().is_empty());
        let egress = payload
            .custom_egress_rego
            .or(current.custom_egress_rego.clone())
            .filter(|s| !s.trim().is_empty());
        let profile = payload.active_profile.unwrap_or_else(|| {
            if ingress.is_some() || egress.is_some() {
                "custom".to_string()
            } else {
                current.active_profile.clone()
            }
        });
        (profile, ingress, egress)
    };

    if active_profile.len() > 64
        || !active_profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "active_profile must be alphanumeric (max 64 chars)",
        ));
    }

    let hop_limit = payload.hop_limit.unwrap_or(current.hop_limit);
    let treb_block_type = payload.treb_block_type.unwrap_or(current.treb_block_type);

    state
        .engine
        .update_policy(
            active_profile.clone(),
            hop_limit,
            treb_block_type,
            custom_ingress.clone(),
            custom_egress.clone(),
        )
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;

    {
        let conn_lock = state.ctx.internal_storage.connection();
        let conn = conn_lock.lock().map_err(|_| {
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "Database lock poisoned")
        })?;
        let now_ts = OffsetDateTime::now_utc().unix_timestamp();

        conn.execute(
            "INSERT INTO rego_policy_config
                (id, active_profile, hop_limit, treb_block_type, custom_ingress_rego, custom_egress_rego, updated_at, updated_by)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, 'webui')
             ON CONFLICT(id) DO UPDATE SET
                active_profile = excluded.active_profile,
                hop_limit = excluded.hop_limit,
                treb_block_type = excluded.treb_block_type,
                custom_ingress_rego = excluded.custom_ingress_rego,
                custom_egress_rego = excluded.custom_egress_rego,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by",
            rusqlite::params![
                active_profile,
                i64::from(hop_limit),
                i64::try_from(treb_block_type).unwrap_or(201),
                custom_ingress,
                custom_egress,
                now_ts,
            ],
        )
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok(Json(PolicyStatusResponse {
        config: state.engine.config(),
        sources: state.engine.policy_sources(),
    }))
}

/// `GET /decisions` - Returns the recent Rego policy decision audit ring buffer.
pub async fn list_decisions(State(state): State<RegoRouteState>) -> Json<Vec<DecisionAuditEntry>> {
    Json(state.engine.decision_log())
}

/// `POST /decisions/clear` - Clears the in-memory decision audit log.
pub async fn clear_decisions(State(state): State<RegoRouteState>) -> StatusCode {
    state.engine.clear_decision_log();
    StatusCode::NO_CONTENT
}

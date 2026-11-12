use crate::{
    api::path_id,
    auth::{self, Auth, Context, Resource},
    error::{Error, Result},
    plugin_catalog,
};
use serde_json::Value;
use std::collections::HashMap;
use tokio_postgres::GenericClient;

pub(super) async fn authorize(
    c: &(impl GenericClient + Sync),
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
) -> Result<()> {
    match name {
        "listTasks" => Ok(()), // The catalog filters each task by current authority.
        "getTask" | "listTaskSteps" => {
            let task = path_id(params, "task_id")?;
            let row = c
                .query_opt("SELECT owner_id FROM tasks WHERE id=$1", &[&task])
                .await?
                .ok_or_else(Error::not_found)?;
            auth::authorize(
                c,
                ctx,
                "task.read",
                &Resource::new("task", task, Some(row.get(0))),
            )
            .await
            .map_err(|error| {
                if error.code == "PERMISSION_DENIED" {
                    Error::not_found()
                } else {
                    error
                }
            })
        }
        _ => Err(Error::not_found()),
    }
}

pub(super) async fn execute(
    c: &(impl GenericClient + Sync),
    auth: &Auth,
    ctx: &Context,
    name: &str,
    params: &HashMap<String, String>,
    query: &str,
) -> Result<(Value, u16)> {
    match name {
        "getTask" => Ok((
            plugin_catalog::read_task(c, path_id(params, "task_id")?, None)
                .await?
                .ok_or_else(Error::not_found)?,
            200,
        )),
        "listTasks" => plugin_catalog::execute(c, auth, ctx, name, query).await,
        "listTaskSteps" => {
            plugin_catalog::list_task_steps(c, auth, ctx, path_id(params, "task_id")?, query).await
        }
        _ => Err(Error::not_found()),
    }
}

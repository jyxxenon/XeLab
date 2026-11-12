//! Task and batch admission-ledger consistency required before an offline
//! metadata export. Source CHECK/unique constraints already enforce reference
//! integrity, one admissible delegation per admitted row and one active attempt
//! per step; this validation catches the cross-table states that binary COPY
//! would faithfully preserve but that no restored executor can resume sanely:
//! a live attempt attached to a terminal step or task, or a live batch item
//! attached to a terminal batch.
//!
//! Executing authority is not preserved here: `recovery::reset_rows` revokes
//! every active execution delegation during import, so restored tasks and
//! batches can never continue with stale admission authority. Rows themselves
//! are ordinary data and are copied like every other snapshot table.
use super::*;

pub(crate) async fn validate_snapshot(c: &(impl GenericClient + Sync)) -> Result<()> {
    let inconsistent: bool = c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN task_steps s ON s.id=a.step_id JOIN tasks t ON t.id=s.task_id WHERE a.state IN ('leased','running') AND (s.state IN ('succeeded','failed','canceled') OR t.state IN ('succeeded','failed','canceled'))) OR EXISTS(SELECT 1 FROM skill_batch_items i JOIN skill_batches b ON b.id=i.batch_id WHERE i.state='running' AND b.state IN ('succeeded','partially_succeeded','failed','canceled'))",
            &[],
        )
        .await?
        .get(0);
    if inconsistent {
        return Err(Error::conflict(
            "Task admission ledger has a live attempt on a terminal step or a live batch item on a terminal batch",
        ));
    }
    Ok(())
}

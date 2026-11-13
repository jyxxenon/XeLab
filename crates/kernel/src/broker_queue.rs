//! Process-local waiters. The database remains authoritative for active slots.
use crate::error::{Error, Result};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use uuid::Uuid;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct Instance {
    pub id: Uuid,
    pub generation: i64,
}

#[derive(Clone)]
pub(crate) struct Queue {
    instances: Arc<Mutex<HashMap<Instance, VecDeque<Arc<Notify>>>>>,
    background_checks: Arc<Semaphore>,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            instances: Default::default(),
            background_checks: Arc::new(Semaphore::new(2)),
        }
    }
}

impl Queue {
    pub(crate) fn has_waiters(&self, instance: Instance) -> bool {
        self.instances.lock().unwrap().contains_key(&instance)
    }

    #[cfg(test)]
    pub(crate) fn len(&self, instance: Instance) -> usize {
        self.instances
            .lock()
            .unwrap()
            .get(&instance)
            .map_or(0, VecDeque::len)
    }

    pub(crate) fn enqueue(
        &self,
        instance: Instance,
        limit: usize,
        deadline: Instant,
    ) -> Result<Ticket> {
        if limit == 0 {
            return Err(Error::exhausted());
        }
        let mut instances = self.instances.lock().unwrap();
        let queue = instances.entry(instance).or_default();
        if queue.len() >= limit {
            return Err(Error::exhausted());
        }
        let wake = Arc::new(Notify::new());
        if queue.is_empty() {
            // A free slot can appear while a wait-only transaction validates
            // the first requester and before it registers the ticket.
            wake.notify_one();
        }
        queue.push_back(wake.clone());
        Ok(Ticket {
            queue: self.clone(),
            instance,
            deadline,
            wake,
        })
    }

    pub(crate) fn wake_head(&self, instance: Instance) {
        if let Some(wake) = self
            .instances
            .lock()
            .unwrap()
            .get(&instance)
            .and_then(VecDeque::front)
        {
            wake.notify_one();
        }
    }
}

pub(crate) struct Ticket {
    queue: Queue,
    pub(crate) instance: Instance,
    pub(crate) deadline: Instant,
    wake: Arc<Notify>,
}

impl Ticket {
    pub(crate) fn is_head(&self) -> bool {
        self.queue
            .instances
            .lock()
            .unwrap()
            .get(&self.instance)
            .and_then(VecDeque::front)
            .is_some_and(|head| Arc::ptr_eq(head, &self.wake))
    }

    pub(crate) async fn wait(&self) {
        // Recheck revocation, health and controller releases that do not come
        // through the normal Call finalizer, even when this waiter is not first.
        let check_at = self.deadline.min(Instant::now() + Duration::from_secs(1));
        tokio::select! {
            _ = self.wake.notified() => {},
            _ = tokio::time::sleep_until(check_at) => {},
        }
    }

    pub(crate) async fn background_permit(&self) -> Result<Option<OwnedSemaphorePermit>> {
        if self.is_head() {
            return Ok(None);
        }
        // A burst of periodic policy checks must leave room for the head and
        // active Call finalizers. Promotion bypasses this background budget.
        tokio::select! {
            _ = tokio::time::sleep_until(self.deadline) => Err(expired()),
            _ = self.wake.notified() => Ok(None),
            permit = self.queue.background_checks.clone().acquire_owned() => {
                Ok(Some(permit.expect("queue background budget is never closed")))
            }
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut instances = self.queue.instances.lock().unwrap();
        let Some(queue) = instances.get_mut(&self.instance) else {
            return;
        };
        let was_head = queue
            .front()
            .is_some_and(|head| Arc::ptr_eq(head, &self.wake));
        queue.retain(|waiter| !Arc::ptr_eq(waiter, &self.wake));
        if queue.is_empty() {
            instances.remove(&self.instance);
        } else if was_head {
            queue.front().unwrap().notify_one();
        }
    }
}

pub(crate) fn supports_manifest(manifest: &Value) -> bool {
    manifest["business_entry"] == "skill_required"
        && manifest["routes"].as_array().is_some_and(Vec::is_empty)
        && manifest["capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().all(|cap| cap["stream_item_schema"].is_null()))
        && manifest["skills"].as_array().is_some_and(|skills| {
            !skills.is_empty()
                && skills
                    .iter()
                    .all(|skill| skill["target"]["kind"] == "capability")
        })
}

pub(crate) fn expired() -> Error {
    Error::new(
        "DEADLINE_EXCEEDED",
        "Call expired while waiting for an instance slot",
        axum::http::StatusCode::GATEWAY_TIMEOUT,
    )
}

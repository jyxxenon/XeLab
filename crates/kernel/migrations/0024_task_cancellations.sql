CREATE INDEX task_cancellations_pending_idx ON tasks(id) WHERE state='cancel_requested';

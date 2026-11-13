CREATE INDEX tasks_deadline_due_idx ON tasks(deadline_at,id)
  WHERE admission IS NOT NULL AND state IN ('queued','running','waiting_dependency');
CREATE INDEX attempts_lease_due_idx ON attempts(lease_expires_at,id)
  WHERE state IN ('leased','running');

-- A Task attempt owns at most one durable Broker Call. A Call has its own
-- short-lived execution delegation, distinct from the Task's frozen grant.
ALTER TABLE attempts ADD COLUMN broker_call_id uuid UNIQUE REFERENCES calls(id);

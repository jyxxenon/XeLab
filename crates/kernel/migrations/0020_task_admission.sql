-- Historical rows may lack a submission proof. Such rows never carry live
-- execution authority merely because they are referenced by a task.
ALTER TABLE tasks ADD COLUMN admission jsonb CHECK (
  admission IS NULL OR (jsonb_typeof(admission) = 'object' AND admission @> '{"version":1}'::jsonb)
);
CREATE UNIQUE INDEX task_admission_delegation_idx ON tasks(delegation_id) WHERE admission IS NOT NULL;

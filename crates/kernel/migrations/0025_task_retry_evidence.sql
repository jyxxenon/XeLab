ALTER TABLE attempts ADD COLUMN dispatch_started boolean
  CHECK (dispatch_started IS NULL OR broker_call_id IS NOT NULL);
ALTER TABLE attempts ADD COLUMN pre_dispatch_failure boolean NOT NULL DEFAULT false
  CHECK (NOT pre_dispatch_failure OR (state='failed' AND broker_call_id IS NULL));

ALTER TABLE task_step_resolutions DROP CONSTRAINT task_step_resolutions_resolution_check;
ALTER TABLE task_step_resolutions ALTER COLUMN output_digest DROP NOT NULL;
ALTER TABLE task_step_resolutions ADD CONSTRAINT task_step_resolution_result_check CHECK (
  (resolution='confirmed_succeeded' AND output_digest IS NOT NULL)
  OR (resolution='confirmed_not_executed' AND output_digest IS NULL)
);

CREATE INDEX calls_owner_idempotency_idx ON calls(owner_id,idempotency_key)
  WHERE idempotency_key IS NOT NULL;

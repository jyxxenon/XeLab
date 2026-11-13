CREATE TABLE task_step_resolutions (
  attempt_id uuid PRIMARY KEY REFERENCES attempts(id),
  call_id uuid NOT NULL UNIQUE REFERENCES calls(id),
  actor_subject_id uuid NOT NULL REFERENCES accounts(id),
  actor_credential_id uuid NOT NULL REFERENCES credentials(id),
  request_id uuid NOT NULL,
  resolution text NOT NULL CHECK (resolution='confirmed_succeeded'),
  evidence text NOT NULL CHECK (char_length(evidence) BETWEEN 1 AND 2048),
  output_digest text NOT NULL CHECK (output_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL
);

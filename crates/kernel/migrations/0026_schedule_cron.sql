ALTER TABLE schedules ADD COLUMN admission jsonb, ADD COLUMN deleted_at timestamptz;
CREATE INDEX schedules_due_idx ON schedules(next_fire_at,id)
    WHERE admission IS NOT NULL AND deleted_at IS NULL AND next_fire_at IS NOT NULL;
CREATE INDEX schedule_fires_pending_idx ON schedule_fires(schedule_id,scheduled_at DESC)
    WHERE outcome='pending';
CREATE INDEX schedule_fires_task_idx ON schedule_fires(task_id,schedule_id)
    WHERE task_id IS NOT NULL;

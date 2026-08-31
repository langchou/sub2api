-- Store the optional second-pass Qwen3Guard result beside the primary audit event.

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS review_result JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_events_review_json'
          AND conrelid = 'prompt_audit_events'::regclass
    ) THEN
        ALTER TABLE prompt_audit_events
            ADD CONSTRAINT chk_prompt_audit_events_review_json
            CHECK (jsonb_typeof(review_result) = 'object');
    END IF;
END $$;

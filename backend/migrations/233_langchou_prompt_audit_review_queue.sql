-- Persist the one-chunk 8B review input without exposing it in event APIs.

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS review_input TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_review_pending
    ON prompt_audit_events(id)
    WHERE review_result->>'status' IN ('queued', 'processing');

package securityaudit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type WorkerRuntime struct {
	active           atomic.Int64
	processed        atomic.Int64
	failed           atomic.Int64
	heartbeatNS      atomic.Int64
	lastProcessedNS  atomic.Int64
	lastErrorMu      sync.RWMutex
	lastErrorCode    string
	lastErrorMessage string
}

type Runner struct {
	config  ConfigStore
	repo    JobRepository
	payload PayloadStore
	scanner PromptScanner
	metrics Metrics
	clock   Clock
	runtime WorkerRuntime

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewRunner(config ConfigStore, repo JobRepository, payload PayloadStore, scanner PromptScanner, metrics Metrics) *Runner {
	return &Runner{config: config, repo: repo, payload: payload, scanner: scanner, metrics: metrics, clock: realClock{}}
}

func (r *Runner) Start(ctx context.Context) error {
	if r == nil || r.config == nil || r.repo == nil || r.payload == nil || r.scanner == nil {
		return errors.New("prompt audit worker dependencies unavailable")
	}
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()
	if err := r.payload.Ping(runCtx); err != nil {
		r.setLastError("payload_store_unavailable", err.Error())
	}
	for workerID := 0; workerID < MaxWorkerCount; workerID++ {
		r.wg.Add(1)
		go r.worker(runCtx, workerID)
	}
	r.wg.Add(1)
	go r.reclaimer(runCtx)
	r.wg.Add(1)
	go r.reviewWorker(runCtx)
	return nil
}

func (r *Runner) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		LogWarn(EventProcessFailed, map[string]any{"status": "shutdown_timeout", "error_code": "worker_shutdown_timeout"})
		return ctx.Err()
	}
}

func (r *Runner) worker(ctx context.Context, workerID int) {
	defer r.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runtime.heartbeatNS.Store(r.clock.Now().UnixNano())
			cfg, ok := r.config.Active()
			if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || workerID >= cfg.WorkerCount {
				continue
			}
			for {
				job, claimed, err := r.repo.ClaimNextJob(ctx, r.clock.Now())
				if err != nil {
					r.setLastError("claim_job_failed", err.Error())
					break
				}
				if !claimed {
					break
				}
				r.runtime.active.Add(1)
				r.processSafely(ctx, workerID, cfg, job)
				r.runtime.active.Add(-1)
			}
		}
	}
}

func (r *Runner) processSafely(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.runtime.failed.Add(1)
			// Panic values may contain scanner response fragments or prompt data.
			// Keep only a stable generic message in runtime state and logs.
			r.setLastError("worker_panic", "worker panic recovered")
			_ = r.repo.Fail(ctx, job.ID, job.ClaimVersion, "worker_panic", "worker panic recovered")
			LogError(EventProcessFailed, mergeLogFields(jobLogFields(job), map[string]any{"worker_id": workerID, "status": "failed", "error_code": "worker_panic"}))
		}
	}()
	if err := r.processJob(ctx, workerID, cfg, job); err != nil {
		r.runtime.failed.Add(1)
	} else {
		r.runtime.processed.Add(1)
		r.runtime.lastProcessedNS.Store(r.clock.Now().UnixNano())
	}
}

func (r *Runner) processJob(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) error {
	baseFields := jobLogFields(job)
	LogInfo(EventAuditStarted, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "attempts": job.Attempts, "status": "processing"}))
	scanText, err := r.payload.Get(ctx, job.ID)
	if err != nil {
		return r.finishFailure(ctx, job, &GuardError{Code: "payload_missing", Retryable: false, Cause: err})
	}
	// The job row only carries redacted metadata; the full prompt for the audit
	// event is reconstructed here from the transient scan payload.
	job.Snapshot.FullPrompt = FullPromptFromScanText(scanText)
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		return r.finishFailure(ctx, job, &GuardError{Code: "no_enabled_endpoint", Retryable: true})
	}
	aggregated, err := r.scanPrompt(ctx, workerID, job, cfg.Scanners, endpoints, scanText, "primary", true, func(ctx context.Context, now time.Time) error {
		return r.repo.RefreshLease(ctx, job.ID, job.ClaimVersion, now)
	})
	if err != nil {
		var guardErr *GuardError
		if !errors.As(err, &guardErr) {
			return err
		}
		return r.finishFailure(ctx, job, guardErr)
	}
	if _, ok := cfg.ReviewEndpoint(); ok && aggregated.Decision != EventPass {
		now := r.clock.Now()
		job.Review = &ReviewOutcome{
			Status: ReviewStatusQueued, MaxAttempts: DefaultReviewAttempts,
			QueuedAt: &now, NextAttemptAt: &now,
		}
	}
	event, err := r.repo.Complete(ctx, job, aggregated, cfg.StorePassEvents)
	if err != nil {
		return err
	}
	if deleteErr := r.payload.Delete(ctx, job.ID); deleteErr != nil {
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "status": "payload_delete_deferred", "error_code": "payload_delete_failed"}))
	}
	LogInfo(EventProcessed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": eventID(event), "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "latency_ms": aggregated.LatencyMS, "status": "done"}))
	if event != nil && job.Review != nil {
		LogInfo(EventReviewQueued, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": event.ID, "decision": aggregated.Decision, "status": ReviewStatusQueued}))
	}
	if event != nil && aggregated.Decision != EventPass {
		LogWarn(EventFindingRecorded, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": event.ID, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "status": "recorded"}))
	}
	return nil
}

func (r *Runner) scanPrompt(ctx context.Context, workerID int, job *Job, scanners []string, endpoints []ActiveEndpoint, scanText, scanStage string, observeMetrics bool, refreshLease func(context.Context, time.Time) error) (*NormalizedResult, error) {
	baseFields := jobLogFields(job)
	inputLimit := minimumInputLimit(endpoints)
	chunks := SplitRunes(scanText, inputLimit)
	results := make([]*NormalizedResult, 0, len(chunks))
	bestReviewInput := ""
	bestSeverity := 0
	started := r.clock.Now()
	for index, chunk := range chunks {
		if refreshLease != nil {
			if err := refreshLease(ctx, r.clock.Now()); err != nil {
				return nil, err
			}
		}
		chunkStarted := r.clock.Now()
		LogInfo(EventChunkStarted, mergeLogFields(baseFields, map[string]any{
			"worker_id": workerID, "scan_stage": scanStage, "chunk_index": index + 1, "chunk_total": len(chunks),
			"chunk_chars": len([]rune(chunk)), "input_chars": job.Snapshot.PromptLength, "input_limit": inputLimit, "status": "started",
		}))
		var metrics Metrics
		if observeMetrics {
			metrics = r.metrics
		}
		result, scanErr := scanWithFailover(ctx, r.scanner, scanners, endpoints, chunk, metrics)
		if scanErr != nil {
			LogWarn(EventChunkFailed, mergeLogFields(baseFields, map[string]any{
				"worker_id": workerID, "scan_stage": scanStage, "chunk_index": index + 1, "chunk_total": len(chunks),
				"chunk_chars": len([]rune(chunk)), "input_chars": job.Snapshot.PromptLength, "input_limit": inputLimit,
				"latency_ms": r.clock.Now().Sub(chunkStarted).Milliseconds(), "error_code": guardErrorCode(scanErr), "status": "failed",
			}))
			if observeMetrics {
				r.observeAsyncFailure(scanErr, r.clock.Now().Sub(started))
			}
			var guardErr *GuardError
			if !errors.As(scanErr, &guardErr) {
				scanErr = &GuardError{Code: guardErrorCode(scanErr), Cause: scanErr}
			}
			return nil, scanErr
		}
		results = append(results, result)
		if severity := resultSeverity(result.Decision); bestReviewInput == "" || severity > bestSeverity {
			bestReviewInput, bestSeverity = chunk, severity
		}
		LogInfo(EventChunkCompleted, mergeLogFields(baseFields, map[string]any{
			"worker_id": workerID, "scan_stage": scanStage, "chunk_index": index + 1, "chunk_total": len(chunks),
			"guard_endpoint_id": result.GuardEndpointID, "action": result.Action,
			"latency_ms": r.clock.Now().Sub(chunkStarted).Milliseconds(), "status": "completed",
		}))
		if result.Action == ActionBlock {
			break
		}
	}
	aggregated, err := AggregateResults(results, r.clock.Now().Sub(started))
	if err != nil {
		if observeMetrics && r.metrics != nil {
			r.metrics.Observe(DecisionInvalid, r.clock.Now().Sub(started))
		}
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	aggregated.ChunkTotal = len(chunks)
	if aggregated.Decision != EventPass {
		aggregated.ReviewInput = bestReviewInput
	}
	if observeMetrics && r.metrics != nil {
		r.metrics.Observe(decisionKindForResult(aggregated), r.clock.Now().Sub(started))
	}
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"worker_id": workerID, "scan_stage": scanStage, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel,
		"action": aggregated.Action, "chunk_total": aggregated.ChunkTotal, "latency_ms": aggregated.LatencyMS,
		"guard_endpoint_id": aggregated.GuardEndpointID, "status": "completed",
	}))
	return aggregated, nil
}

func (r *Runner) reviewWorker(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg, ok := r.config.Active()
			if !ok || !cfg.RiskControlEnabled || !cfg.Enabled {
				continue
			}
			endpoint, ok := cfg.ReviewEndpoint()
			if !ok {
				continue
			}
			for {
				event, claimed, err := r.repo.ClaimNextReview(ctx, r.clock.Now())
				if err != nil {
					r.setLastError("claim_review_failed", err.Error())
					break
				}
				if !claimed {
					break
				}
				r.processReviewSafely(ctx, cfg, endpoint, event)
			}
		}
	}
}

func (r *Runner) processReviewSafely(ctx context.Context, cfg ActiveConfig, endpoint ActiveEndpoint, event *Event) {
	defer func() {
		if recover() == nil || event == nil || event.Review == nil {
			return
		}
		now := r.clock.Now()
		outcome := cloneReviewOutcome(event.Review)
		outcome.Status, outcome.ErrorCode = ReviewStatusFailed, "review_worker_panic"
		outcome.Result, outcome.ProcessingStartedAt, outcome.NextAttemptAt = nil, nil, nil
		outcome.CompletedAt = &now
		_ = r.repo.UpdateReview(ctx, event.ID, event.Review.ClaimVersion, outcome)
		r.setLastError(outcome.ErrorCode, "review worker panic recovered")
		LogError(EventReviewFailed, mergeLogFields(eventLogFields(event), map[string]any{"worker_id": 0, "status": ReviewStatusFailed, "error_code": outcome.ErrorCode}))
	}()
	if err := r.processReview(ctx, cfg, endpoint, event); err != nil {
		r.setLastError(guardErrorCode(err), err.Error())
	}
}

func (r *Runner) processReview(ctx context.Context, cfg ActiveConfig, endpoint ActiveEndpoint, event *Event) error {
	if event == nil || event.Review == nil {
		return errors.New("prompt audit review event unavailable")
	}
	baseFields := eventLogFields(event)
	LogInfo(EventReviewStarted, mergeLogFields(baseFields, map[string]any{
		"worker_id": 0, "guard_endpoint_id": endpoint.ID, "decision": event.Decision, "status": ReviewStatusProcessing,
	}))
	job := &Job{
		ID: event.JobID, Snapshot: event.Snapshot, ConfigVersion: event.ConfigVersion,
		ClaimVersion: event.Review.ClaimVersion, Attempts: event.Review.Attempts, MaxAttempts: event.Review.MaxAttempts,
	}
	if job.Snapshot.ScanText == "" {
		return r.finishReviewFailure(ctx, event, &GuardError{Code: "review_input_missing", Retryable: false})
	}
	result, err := r.scanPrompt(ctx, 0, job, cfg.Scanners, []ActiveEndpoint{endpoint}, job.Snapshot.ScanText, "review", false, func(ctx context.Context, now time.Time) error {
		return r.repo.RefreshReviewLease(ctx, event.ID, event.Review.ClaimVersion, now)
	})
	if err != nil {
		return r.finishReviewFailure(ctx, event, err)
	}
	now := r.clock.Now()
	outcome := cloneReviewOutcome(event.Review)
	outcome.Status, outcome.Result, outcome.ErrorCode = ReviewStatusCompleted, result, ""
	outcome.ProcessingStartedAt, outcome.NextAttemptAt = nil, nil
	outcome.CompletedAt = &now
	if err := r.repo.UpdateReview(ctx, event.ID, event.Review.ClaimVersion, outcome); err != nil {
		return err
	}
	LogInfo(EventReviewCompleted, mergeLogFields(baseFields, map[string]any{
		"worker_id": 0, "guard_endpoint_id": endpoint.ID, "decision": result.Decision,
		"risk_level": result.RiskLevel, "action": result.Action, "latency_ms": result.LatencyMS, "status": ReviewStatusCompleted,
	}))
	return nil
}

func (r *Runner) finishReviewFailure(ctx context.Context, event *Event, err error) error {
	code := guardErrorCode(err)
	retryable := false
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		retryable = guardErr.Retryable
	}
	now := r.clock.Now()
	outcome := cloneReviewOutcome(event.Review)
	outcome.Result, outcome.ProcessingStartedAt = nil, nil
	outcome.ErrorCode = code
	if retryable && outcome.Attempts < outcome.MaxAttempts {
		next := now.Add(retryBackoff(outcome.Attempts))
		outcome.Status, outcome.NextAttemptAt, outcome.CompletedAt = ReviewStatusQueued, &next, nil
	} else {
		outcome.Status, outcome.NextAttemptAt, outcome.CompletedAt = ReviewStatusFailed, nil, &now
	}
	if updateErr := r.repo.UpdateReview(ctx, event.ID, event.Review.ClaimVersion, outcome); updateErr != nil {
		return updateErr
	}
	LogWarn(EventReviewFailed, mergeLogFields(eventLogFields(event), map[string]any{
		"worker_id": 0, "status": outcome.Status, "error_code": code, "retryable": retryable,
		"attempts": outcome.Attempts, "max_attempts": outcome.MaxAttempts,
	}))
	return err
}

func (r *Runner) observeAsyncFailure(err error, latency time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	kind := DecisionUnavailable
	if guardErrorCode(err) == ErrorCodeInvalidResponse {
		kind = DecisionInvalid
	}
	r.metrics.Observe(kind, latency)
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Timeout {
		r.metrics.IncTimeout()
	}
}

func decisionKindForResult(result *NormalizedResult) DecisionKind {
	if result == nil {
		return DecisionInvalid
	}
	switch result.Action {
	case ActionBlock:
		return DecisionBlock
	case ActionWarn:
		return DecisionFlag
	default:
		return DecisionAllow
	}
}

func (r *Runner) finishFailure(ctx context.Context, job *Job, err error) error {
	baseFields := jobLogFields(job)
	code := guardErrorCode(err)
	retryable := false
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		retryable = guardErr.Retryable
	}
	if retryable && job.Attempts < job.MaxAttempts {
		next := r.clock.Now().Add(retryBackoff(job.Attempts))
		if updateErr := r.repo.Retry(ctx, job.ID, job.ClaimVersion, next, code, "prompt guard temporarily unavailable"); updateErr != nil {
			return updateErr
		}
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "retry", "error_code": code, "retryable": true}))
	} else {
		if updateErr := r.repo.Fail(ctx, job.ID, job.ClaimVersion, code, "prompt guard processing failed"); updateErr != nil {
			return updateErr
		}
		_ = r.payload.Delete(ctx, job.ID)
		LogError(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "failed", "error_code": code, "retryable": false}))
	}
	r.setLastError(code, err.Error())
	return err
}

func (r *Runner) reclaimer(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := r.clock.Now()
			processingLease := time.Duration(MaxReviewTimeoutMS)*time.Millisecond + 30*time.Second
			count, err := r.repo.ReclaimStale(ctx, now.Add(-2*time.Minute), now.Add(-processingLease), 100)
			if err != nil {
				r.setLastError("reclaim_failed", err.Error())
				continue
			}
			if count > 0 {
				LogWarn(EventProcessingReclaimed, map[string]any{"reclaimed_total": count, "status": "reclaimed"})
			}
			reviewCount, reviewErr := r.repo.ReclaimStaleReviews(ctx, now.Add(-processingLease), 100)
			if reviewErr != nil {
				r.setLastError("review_reclaim_failed", reviewErr.Error())
				continue
			}
			if reviewCount > 0 {
				LogWarn(EventProcessingReclaimed, map[string]any{"reclaimed_total": reviewCount, "scan_stage": "review", "status": "reclaimed"})
			}
		}
	}
}

func (r *Runner) Snapshot() (active, processed, failed int64, heartbeat, lastProcessed *time.Time, code, message string) {
	if r == nil {
		return
	}
	active, processed, failed = r.runtime.active.Load(), r.runtime.processed.Load(), r.runtime.failed.Load()
	if ns := r.runtime.heartbeatNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		heartbeat = &value
	}
	if ns := r.runtime.lastProcessedNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		lastProcessed = &value
	}
	r.runtime.lastErrorMu.RLock()
	code, message = r.runtime.lastErrorCode, r.runtime.lastErrorMessage
	r.runtime.lastErrorMu.RUnlock()
	return
}

func (r *Runner) setLastError(code, _ string) {
	code, message := sanitizeStoredError(code)
	r.runtime.lastErrorMu.Lock()
	r.runtime.lastErrorCode = code
	r.runtime.lastErrorMessage = message
	r.runtime.lastErrorMu.Unlock()
}

func scanWithFailover(ctx context.Context, scanner PromptScanner, scanners []string, endpoints []ActiveEndpoint, chunk string, metrics Metrics) (*NormalizedResult, error) {
	var lastErr error
	for index, endpoint := range endpoints {
		result, err := scanner.Scan(ctx, endpoint, chunk, scanners)
		if err == nil && result != nil {
			return result, nil
		}
		if err == nil {
			err = &GuardError{Code: ErrorCodeInvalidResponse, Retryable: false}
		}
		lastErr = err
		var guardErr *GuardError
		if !errors.As(err, &guardErr) || !guardErr.Retryable {
			return nil, err
		}
		if index < len(endpoints)-1 && metrics != nil {
			metrics.IncFailover()
		}
	}
	if lastErr == nil {
		lastErr = &GuardError{Code: ErrorCodeUnavailable}
	}
	return nil, lastErr
}

func retryBackoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 5 * time.Second
	case 2:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func eventID(event *Event) int64 {
	if event == nil {
		return 0
	}
	return event.ID
}

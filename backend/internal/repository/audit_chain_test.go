package repository

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var chainTestDBCounter atomic.Int64

func newChainTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:chain-test-%d?mode=memory&cache=shared&_pragma=busy_timeout(5000)", chainTestDBCounter.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.AuditChainAnchor{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
	return db
}

func sampleAuditLog(index int) *model.AuditLog {
	return &model.AuditLog{
		RequestID:   fmt.Sprintf("req-%d", index),
		Actor:       "tester",
		Action:      "transition",
		EntityType:  "LabSample",
		EntityID:    uint(index),
		BeforeState: "received",
		AfterState:  "accepted",
		Detail:      fmt.Sprintf("audit %d", index),
		CreatedAt:   time.Date(2026, 9, 26, 8, 0, 0, int(time.Millisecond)*index, time.UTC),
	}
}

func TestAppendAuditChainLinksSequentially(t *testing.T) {
	db := newChainTestDB(t)
	repo := NewSecurityRepository(db)
	ctx := context.Background()

	const count = 5
	for i := 1; i <= count; i++ {
		if err := repo.AppendAuditChain(ctx, sampleAuditLog(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	logs, err := repo.ListAuditsInChainOrder(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != count {
		t.Fatalf("expected %d logs, got %d", count, len(logs))
	}
	prev := model.AuditGenesisFingerprint
	for i, log := range logs {
		seq := uint64(i + 1)
		if log.Seq == nil || *log.Seq != seq {
			t.Fatalf("log %d: expected seq %d, got %v", i, seq, log.Seq)
		}
		if log.PrevFingerprint != prev {
			t.Fatalf("log %d: prev fingerprint not linked", i)
		}
		expected := model.ComputeAuditFingerprint(seq, prev, log)
		if log.Fingerprint != expected {
			t.Fatalf("log %d: fingerprint mismatch", i)
		}
		prev = log.Fingerprint
	}
	anchor, err := repo.GetAuditChainAnchor(ctx)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if anchor.LastSeq != count || anchor.LastFingerprint != prev {
		t.Fatalf("anchor not at chain tail: %+v", anchor)
	}
}

func TestAppendAuditChainConcurrentOrdering(t *testing.T) {
	db := newChainTestDB(t)
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatalf("wal: %v", err)
	}
	repo := NewSecurityRepository(db)
	ctx := context.Background()

	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if err := repo.AppendAuditChain(ctx, sampleAuditLog(worker*100+j)); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	logs, err := repo.ListAuditsInChainOrder(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != workers*3 {
		t.Fatalf("expected %d logs, got %d", workers*3, len(logs))
	}
	seen := make(map[uint64]bool, len(logs))
	prev := model.AuditGenesisFingerprint
	for i, log := range logs {
		if log.Seq == nil || *log.Seq != uint64(i+1) {
			t.Fatalf("seq gap/order problem at %d: %v", i, log.Seq)
		}
		if seen[*log.Seq] {
			t.Fatalf("duplicate seq %d", *log.Seq)
		}
		seen[*log.Seq] = true
		if log.PrevFingerprint != prev {
			t.Fatalf("concurrent append broke linkage at seq %d", *log.Seq)
		}
		if model.ComputeAuditFingerprint(*log.Seq, prev, log) != log.Fingerprint {
			t.Fatalf("fingerprint mismatch at seq %d", *log.Seq)
		}
		prev = log.Fingerprint
	}
}

func TestEnsureAuditChainBackfillsLegacyRows(t *testing.T) {
	db := newChainTestDB(t)
	ctx := context.Background()

	// 模拟链功能上线前的历史记录：没有 seq 和指纹。
	legacy := []model.AuditLog{
		{RequestID: "old-1", Actor: "admin", Action: "create", EntityType: "LabSample", EntityID: 1, CreatedAt: time.Now().UTC()},
		{RequestID: "old-2", Actor: "admin", Action: "update", EntityType: "LabSample", EntityID: 1, CreatedAt: time.Now().UTC().Add(time.Second)},
	}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	repo := NewSecurityRepository(db)
	if err := repo.EnsureAuditChain(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// 再跑一次必须幂等，不重写序号。
	if err := repo.EnsureAuditChain(ctx); err != nil {
		t.Fatalf("ensure idempotency: %v", err)
	}

	logs, err := repo.ListAuditsInChainOrder(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != 2 || logs[0].Seq == nil || *logs[0].Seq != 1 || logs[1].Seq == nil || *logs[1].Seq != 2 {
		t.Fatalf("backfill seqs wrong: %+v", logs)
	}
	if logs[0].PrevFingerprint != model.AuditGenesisFingerprint {
		t.Fatalf("legacy genesis prev must be genesis constant")
	}
	if logs[1].PrevFingerprint != logs[0].Fingerprint {
		t.Fatalf("legacy rows not linked")
	}

	// 回填之后追加的新记录必须从 3 接上。
	if err := repo.AppendAuditChain(ctx, sampleAuditLog(3)); err != nil {
		t.Fatalf("append after backfill: %v", err)
	}
	logs, _ = repo.ListAuditsInChainOrder(ctx)
	if len(logs) != 3 || *logs[2].Seq != 3 || logs[2].PrevFingerprint != logs[1].Fingerprint {
		t.Fatalf("new append did not continue from backfilled tail")
	}
}

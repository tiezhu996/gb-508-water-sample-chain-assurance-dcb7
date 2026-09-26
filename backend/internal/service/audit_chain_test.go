package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/config"
	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
	"github.com/blueship581/water-sample-chain-assurance/backend/internal/repository"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newChainTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	return db
}

func appendSealed(t *testing.T, repo repository.SecurityRepository, index int) {
	t.Helper()
	err := repo.AppendChainedAudit(context.Background(), &model.AuditLog{
		RequestID:   fmt.Sprintf("req-%d", index),
		Actor:       "admin",
		Action:      "transition",
		EntityType:  "SamplingBatch",
		EntityID:    uint(index),
		BeforeState: "planned",
		AfterState:  "collecting",
		Detail:      fmt.Sprintf("record %d", index),
		CreatedAt:   time.Date(2026, 9, 26, 8, 0, index, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("append chained audit %d: %v", index, err)
	}
}

func TestAuditChainIntact(t *testing.T) {
	db := newChainTestDB(t)
	repo := repository.NewSecurityRepository(db)
	svc := NewSecurityService(repo, config.Config{})
	for i := 1; i <= 5; i++ {
		appendSealed(t, repo, i)
	}
	report, err := svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !report.Intact || report.Total != 5 || report.Verified != 5 {
		t.Fatalf("expected 5 intact records, got %+v", report)
	}
	if report.FirstBreakSeq != 0 {
		t.Fatalf("unexpected first break: %+v", report)
	}
}

func TestAuditChainDetectsTamperedRecord(t *testing.T) {
	db := newChainTestDB(t)
	repo := repository.NewSecurityRepository(db)
	svc := NewSecurityService(repo, config.Config{})
	for i := 1; i <= 4; i++ {
		appendSealed(t, repo, i)
	}
	if err := db.Exec("UPDATE audit_logs SET detail = ? WHERE seq = ?", "rewritten after sealing", 2).Error; err != nil {
		t.Fatal(err)
	}
	report, err := svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if report.Intact {
		t.Fatal("tampered chain must not be reported intact")
	}
	if report.FirstBreakSeq != 2 || report.FirstBreakReason != model.AuditBreakTampered {
		t.Fatalf("expected first tamper at seq 2, got seq=%d reason=%q", report.FirstBreakSeq, report.FirstBreakReason)
	}
	if len(report.Breaks) != 1 {
		t.Fatalf("only the edited record should break, got %d breaks", len(report.Breaks))
	}
	// Records stay readable while the chain is broken.
	var count int64
	if err := db.Model(&model.AuditLog{}).Count(&count).Error; err != nil || count != 4 {
		t.Fatalf("records must remain browsable, count=%d err=%v", count, err)
	}
}

func TestAuditChainDetectsMissingRecord(t *testing.T) {
	db := newChainTestDB(t)
	repo := repository.NewSecurityRepository(db)
	svc := NewSecurityService(repo, config.Config{})
	for i := 1; i <= 4; i++ {
		appendSealed(t, repo, i)
	}
	if err := db.Unscoped().Where("seq = ?", 3).Delete(&model.AuditLog{}).Error; err != nil {
		t.Fatal(err)
	}
	report, err := svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if report.Intact || report.Total != 3 {
		t.Fatalf("expected broken chain over 3 remaining rows, got %+v", report)
	}
	if report.FirstBreakSeq != 4 || report.FirstBreakReason != model.AuditBreakGap {
		t.Fatalf("expected gap to surface at the record after the hole (seq 4), got seq=%d reason=%q",
			report.FirstBreakSeq, report.FirstBreakReason)
	}
}

func TestAuditChainConcurrentAppendsStayOrdered(t *testing.T) {
	db := newChainTestDB(t)
	repo := repository.NewSecurityRepository(db)
	svc := NewSecurityService(repo, config.Config{})

	const goroutines = 12
	const perGoroutine = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			for i := 0; i < perGoroutine; i++ {
				err := svc.Audit(context.Background(),
					fmt.Sprintf("operator-%d", g), fmt.Sprintf("req-%d-%d", g, i),
					"transition", "LabSample", uint(g*perGoroutine+i),
					"received", "accepted", "concurrent append")
				if err != nil {
					errs <- err
				}
			}
		}(g)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append failed: %v", err)
	}

	report, err := svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !report.Intact || report.Total != goroutines*perGoroutine || report.Verified != int64(goroutines*perGoroutine) {
		t.Fatalf("concurrent appends must form one intact chain, got %+v", report)
	}

	var seqs []uint
	if err := db.Model(&model.AuditLog{}).Order("seq ASC").Pluck("seq", &seqs).Error; err != nil {
		t.Fatal(err)
	}
	if len(seqs) != goroutines*perGoroutine {
		t.Fatalf("expected %d rows", goroutines*perGoroutine)
	}
	for i, seq := range seqs {
		if seq != uint(i+1) {
			t.Fatalf("seq must be contiguous from 1, mismatch at position %d: got %d", i, seq)
		}
	}
}

func TestBackfillAuditChainSealsLegacyRows(t *testing.T) {
	db := newChainTestDB(t)
	repo := repository.NewSecurityRepository(db)
	svc := NewSecurityService(repo, config.Config{})

	// Simulate rows written before fingerprinting existed.
	legacy := []model.AuditLog{
		{RequestID: "old-1", Actor: "system", Action: "create", EntityType: "AssayMethod", EntityID: 1, AfterState: "draft", CreatedAt: time.Now().UTC()},
		{RequestID: "old-2", Actor: "admin", Action: "update", EntityType: "AssayMethod", EntityID: 1, CreatedAt: time.Now().UTC()},
	}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.BackfillAuditChain(context.Background()); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	// Idempotent: a second run must not change anything.
	if err := repo.BackfillAuditChain(context.Background()); err != nil {
		t.Fatalf("backfill second run: %v", err)
	}
	report, err := svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !report.Intact || report.Total != 2 || report.Verified != 2 || report.Legacy != 0 {
		t.Fatalf("backfilled chain must verify intact, got %+v", report)
	}

	// New sealed writes continue directly from the backfilled tip.
	appendSealed(t, repo, 3)
	report, err = svc.AuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !report.Intact || report.Total != 3 {
		t.Fatalf("new record must extend backfilled chain, got %+v", report)
	}
}

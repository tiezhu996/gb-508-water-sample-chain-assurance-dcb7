package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/config"
	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
	"github.com/blueship581/water-sample-chain-assurance/backend/internal/repository"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newChainService(t *testing.T) (*gorm.DB, SecurityService) {
	t.Helper()
	dsn := fmt.Sprintf("file:chain-svc-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.AuditChainAnchor{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewSecurityRepository(db)
	if err := repo.EnsureAuditChain(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	svc := NewSecurityService(repo, config.Config{})
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
	return db, svc
}

func appendN(t *testing.T, svc SecurityService, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		err := svc.Audit(ctx, "tester", fmt.Sprintf("req-%d", i), "transition", "LabSample",
			uint(i), "received", "accepted", fmt.Sprintf("audit number %d", i))
		if err != nil {
			t.Fatalf("audit %d: %v", i, err)
		}
	}
}

func TestAuditChainIntact(t *testing.T) {
	_, svc := newChainService(t)
	appendN(t, svc, 6)

	status, err := svc.AuditChainStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Intact || status.FirstIssue != nil {
		t.Fatalf("expected intact chain, got issue %+v", status.FirstIssue)
	}
	if status.Total != 6 || status.LastSeq != 6 || status.VerifiedCount != 6 {
		t.Fatalf("unexpected counts: %+v", status)
	}
	if !status.AnchorConsistent {
		t.Fatalf("anchor must be consistent")
	}
	if status.GenesisHash == "" {
		t.Fatalf("genesis hash should be exposed")
	}
}

func TestAuditChainDetectsTamperedContent(t *testing.T) {
	db, svc := newChainService(t)
	appendN(t, svc, 4)

	// 直接改库里的一条记录内容，模拟有人手工动过审计数据。
	if err := db.Exec("UPDATE audit_logs SET detail = ? WHERE seq = ?", "tampered detail", 2).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	status, err := svc.AuditChainStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Intact || status.FirstIssue == nil {
		t.Fatalf("expected broken chain")
	}
	if status.FirstIssue.Seq != 2 || status.FirstIssue.Kind != model.AuditChainIssueTampered {
		t.Fatalf("expected first issue tampered at seq 2, got %+v", status.FirstIssue)
	}
}

func TestAuditChainDetectsMissingMiddleRecord(t *testing.T) {
	db, svc := newChainService(t)
	appendN(t, svc, 5)

	if err := db.Exec("DELETE FROM audit_logs WHERE seq = ?", 3).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	status, err := svc.AuditChainStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Intact || status.FirstIssue == nil {
		t.Fatalf("expected broken chain")
	}
	if status.FirstIssue.Seq != 3 || status.FirstIssue.Kind != model.AuditChainIssueMissing {
		t.Fatalf("expected first issue missing seq 3, got %+v", status.FirstIssue)
	}
	// 第 4 条的前指纹此时指向已删除的第 3 条，应同时报断链。
	foundBroken := false
	for _, issue := range status.Issues {
		if issue.Kind == model.AuditChainIssueBrokenLink && issue.Seq == 4 {
			foundBroken = true
		}
	}
	if !foundBroken {
		t.Fatalf("expected broken_link at seq 4, issues=%+v", status.Issues)
	}
	if status.Total != 4 {
		t.Fatalf("total must count remaining rows, got %d", status.Total)
	}
}

func TestAuditChainDetectsDeletedTailViaAnchor(t *testing.T) {
	db, svc := newChainService(t)
	appendN(t, svc, 5)

	// 删掉最后两条：相邻记录校验看不出尾部缺失，必须靠锚点发现。
	if err := db.Exec("DELETE FROM audit_logs WHERE seq >= ?", 4).Error; err != nil {
		t.Fatalf("delete tail: %v", err)
	}

	status, err := svc.AuditChainStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Intact || status.AnchorConsistent {
		t.Fatalf("expected anchor inconsistency after tail deletion")
	}
	if status.FirstIssue == nil || status.FirstIssue.Kind != model.AuditChainIssueMissing || status.FirstIssue.Seq != 4 {
		t.Fatalf("expected first issue missing seq 4, got %+v", status.FirstIssue)
	}
}

func TestAuditChainDetectsForgedFingerprint(t *testing.T) {
	db, svc := newChainService(t)
	appendN(t, svc, 3)

	// 改内容同时伪造该行指纹，让“内容对不上”消失；但下一条记录里保存的
	// 前指纹仍然指向旧指纹，断链会在相邻的第 2 条暴露。
	if err := db.Exec("UPDATE audit_logs SET detail = ?, fingerprint = ? WHERE seq = ?",
		"forged", "deadbeef", 1).Error; err != nil {
		t.Fatalf("forge: %v", err)
	}

	status, err := svc.AuditChainStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Intact || status.FirstIssue == nil {
		t.Fatalf("expected broken chain after forgery")
	}
	if status.FirstIssue.Seq != 1 || status.FirstIssue.Kind != model.AuditChainIssueTampered {
		t.Fatalf("expected tampered at seq 1, got %+v", status.FirstIssue)
	}
}

func TestListAuditsStillWorksWhenChainBroken(t *testing.T) {
	db, svc := newChainService(t)
	appendN(t, svc, 4)
	if err := db.Exec("DELETE FROM audit_logs WHERE seq = ?", 2).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}

	entries, total, err := svc.ListAudits(context.Background(), 1, 20, "")
	if err != nil {
		t.Fatalf("list must stay readable when chain broken: %v", err)
	}
	if total != 3 || len(entries) != 3 {
		t.Fatalf("expected all remaining rows to be browsable, total=%d len=%d", total, len(entries))
	}
	flagged := map[uint64]bool{}
	for _, entry := range entries {
		if entry.Seq != nil && !entry.ChainOK {
			flagged[*entry.Seq] = true
		}
	}
	if !flagged[3] {
		t.Fatalf("seq 3 (link after deleted row) should be flagged, got %+v", flagged)
	}
}

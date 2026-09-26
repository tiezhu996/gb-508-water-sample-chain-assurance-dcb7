package model

import (
	"testing"
	"time"
)

func TestComputeAuditFingerprintIsDeterministicAndChained(t *testing.T) {
	log := AuditLog{
		RequestID: "req-1", Actor: "admin", Action: "transition", EntityType: "LabSample",
		EntityID: 7, BeforeState: "received", AfterState: "accepted", Detail: "ok",
		CreatedAt: time.Date(2026, 9, 26, 8, 30, 15, 123999000, time.UTC), // 纳秒部分应被截到毫秒
	}
	first := ComputeAuditFingerprint(1, AuditGenesisFingerprint, log)
	again := ComputeAuditFingerprint(1, AuditGenesisFingerprint, log)
	if first != again {
		t.Fatalf("fingerprint must be deterministic")
	}
	if len(first) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(first))
	}

	tampered := log
	tampered.Detail = "changed"
	if ComputeAuditFingerprint(1, AuditGenesisFingerprint, tampered) == first {
		t.Fatalf("content change must change fingerprint")
	}
	otherPrev := ComputeAuditFingerprint(1, "a"+AuditGenesisFingerprint[1:], log)
	if otherPrev == first {
		t.Fatalf("different previous fingerprint must change fingerprint")
	}
	otherSeq := ComputeAuditFingerprint(2, AuditGenesisFingerprint, log)
	if otherSeq == first {
		t.Fatalf("different sequence must change fingerprint")
	}
	// 亚毫秒差异不应改变指纹，与数据库毫秒存储对齐。
	log2 := log
	log2.CreatedAt = log.CreatedAt.Add(500 * time.Nanosecond)
	if ComputeAuditFingerprint(1, AuditGenesisFingerprint, log2) != first {
		t.Fatalf("sub-millisecond time drift must not change fingerprint")
	}
}

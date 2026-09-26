package model

import (
	"testing"
	"time"
)

func TestComputeAuditFingerprintChainsRecords(t *testing.T) {
	created := time.Date(2026, 9, 26, 8, 0, 0, 0, time.UTC)
	first := AuditLog{
		ID: 1, Seq: uintPtr(1), PrevFingerprint: GenesisFingerprint,
		RequestID: "req-1", Actor: "admin", Action: "create", EntityType: "SamplingBatch",
		EntityID: 7, BeforeState: "", AfterState: "planned", Detail: "created", CreatedAt: created,
	}
	first.Fingerprint = ComputeAuditFingerprint(first)
	if len(first.Fingerprint) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(first.Fingerprint))
	}

	second := AuditLog{
		ID: 2, Seq: uintPtr(2), PrevFingerprint: first.Fingerprint,
		RequestID: "req-2", Actor: "operator", Action: "transition", EntityType: "SamplingBatch",
		EntityID: 7, BeforeState: "planned", AfterState: "collecting", Detail: "", CreatedAt: created.Add(time.Second),
	}
	second.Fingerprint = ComputeAuditFingerprint(second)

	if second.Fingerprint == first.Fingerprint {
		t.Fatal("fingerprints for different records must differ")
	}

	tampered := first
	tampered.Detail = "changed by someone"
	if ComputeAuditFingerprint(tampered) == first.Fingerprint {
		t.Fatal("changing content must change the fingerprint")
	}

	relinked := second
	relinked.PrevFingerprint = GenesisFingerprint
	if ComputeAuditFingerprint(relinked) == second.Fingerprint {
		t.Fatal("changing the previous fingerprint must change the fingerprint")
	}
}

func TestAuditCanonicalTimeIsStable(t *testing.T) {
	value := time.Date(2026, 9, 26, 8, 0, 0, 123_999_999, time.UTC)
	if got := AuditCanonicalTime(value); got != "2026-09-26T08:00:00.123Z" {
		t.Fatalf("unexpected canonical time %q", got)
	}
	loc := time.FixedZone("UTC+8", 8*3600)
	if got := AuditCanonicalTime(value.In(loc)); got != "2026-09-26T08:00:00.123Z" {
		t.Fatalf("canonical time must normalize timezone, got %q", got)
	}
}

func uintPtr(value uint) *uint { return &value }

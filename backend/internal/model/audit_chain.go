package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenesisFingerprint is the previous fingerprint of the first audit record.
const GenesisFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

// Audit chain break reasons surfaced to handlers and the audit page.
const (
	AuditBreakLegacy     = "legacy"     // record predates fingerprinting, never sealed
	AuditBreakGap        = "gap"        // a preceding record is missing
	AuditBreakTampered   = "tampered"   // record content changed after sealing
	AuditBreakBrokenLink = "brokenLink" // stored previous fingerprint disagrees with the chain
)

// AuditChainBreak points at one record that fails chain verification.
type AuditChainBreak struct {
	Seq                     uint   `json:"seq"`
	ID                      uint   `json:"id"`
	Reason                  string `json:"reason"`
	ExpectedFingerprint     string `json:"expectedFingerprint,omitempty"`
	StoredFingerprint       string `json:"storedFingerprint,omitempty"`
	ExpectedPrevFingerprint string `json:"expectedPrevFingerprint,omitempty"`
	StoredPrevFingerprint   string `json:"storedPrevFingerprint,omitempty"`
}

// AuditChainReport is the integrity verdict for the whole audit trail.
type AuditChainReport struct {
	Intact           bool              `json:"intact"`
	Total            int64             `json:"total"`
	Verified         int64             `json:"verified"`
	Legacy           int64             `json:"legacy"`
	FirstBreakSeq    uint              `json:"firstBreakSeq"`
	FirstBreakID     uint              `json:"firstBreakId"`
	FirstBreakReason string            `json:"firstBreakReason,omitempty"`
	LastSeq          uint              `json:"lastSeq"`
	LastFingerprint  string            `json:"lastFingerprint,omitempty"`
	Breaks           []AuditChainBreak `json:"breaks"`
}

// AuditCanonicalTime renders the timestamp covered by a fingerprint.
// Millisecond precision is the common denominator of MySQL DATETIME(3),
// PostgreSQL timestamps and SQLite via GORM.
func AuditCanonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// ComputeAuditFingerprint derives the fingerprint of one audit record from
// its chain position, the previous record's fingerprint and the immutable
// record content. Fingerprint fields themselves are deliberately excluded.
func ComputeAuditFingerprint(log AuditLog) string {
	seq := uint(0)
	if log.Seq != nil {
		seq = *log.Seq
	}
	lines := []string{
		"audit-log/v1",
		fmt.Sprint(seq),
		log.PrevFingerprint,
		strings.TrimSpace(log.RequestID),
		strings.TrimSpace(log.Actor),
		strings.TrimSpace(log.Action),
		strings.TrimSpace(log.EntityType),
		fmt.Sprint(log.EntityID),
		strings.TrimSpace(log.BeforeState),
		strings.TrimSpace(log.AfterState),
		strings.TrimSpace(log.Detail),
		AuditCanonicalTime(log.CreatedAt),
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// ExpectedFingerprint recomputes the fingerprint a sealed record should carry.
func (log AuditLog) ExpectedFingerprint() string {
	return ComputeAuditFingerprint(log)
}

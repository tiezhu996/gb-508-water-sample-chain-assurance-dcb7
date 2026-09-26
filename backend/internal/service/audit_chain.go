package service

import (
	"context"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
)

// AuditChain verifies the whole fingerprint chain and returns a report that
// stays readable even when the chain is broken: verification never fails the
// request because of tampering, it reports where the mismatch starts.
func (s *securityService) AuditChain(ctx context.Context) (model.AuditChainReport, error) {
	logs, err := s.repository.ListAuditsChain(ctx)
	if err != nil {
		return model.AuditChainReport{}, err
	}

	report := model.AuditChainReport{
		Total:  int64(len(logs)),
		Breaks: make([]model.AuditChainBreak, 0),
	}
	if len(logs) == 0 {
		report.Intact = true
		return report, nil
	}

	expectedSeq := uint(1)
	expectedPrev := model.GenesisFingerprint

	for i := range logs {
		log := logs[i]
		sealed := log.Seq != nil && log.Fingerprint != "" && log.PrevFingerprint != ""

		var reason string
		breakRecord := model.AuditChainBreak{ID: log.ID}
		if log.Seq != nil {
			breakRecord.Seq = *log.Seq
		}

		switch {
		case !sealed:
			reason = model.AuditBreakLegacy
			report.Legacy++
		case *log.Seq != expectedSeq:
			// A record is missing before this one (deletion or out-of-chain row).
			reason = model.AuditBreakGap
		case log.ExpectedFingerprint() != log.Fingerprint:
			// Content was changed after the record was sealed.
			reason = model.AuditBreakTampered
			breakRecord.ExpectedFingerprint = log.ExpectedFingerprint()
			breakRecord.StoredFingerprint = log.Fingerprint
		case log.PrevFingerprint != expectedPrev:
			// Link disagrees: either this link field was edited or an
			// earlier record was replaced after this one was sealed.
			reason = model.AuditBreakBrokenLink
			breakRecord.ExpectedPrevFingerprint = expectedPrev
			breakRecord.StoredPrevFingerprint = log.PrevFingerprint
		}

		if reason == "" {
			report.Verified++
		} else {
			breakRecord.Reason = reason
			report.Breaks = append(report.Breaks, breakRecord)
		}

		// Advance the expected chain position. For legacy (unsealed) rows we
		// still follow their id order so later gap detection stays anchored.
		if log.Seq != nil {
			expectedSeq = *log.Seq + 1
			if log.Fingerprint != "" {
				expectedPrev = log.Fingerprint
			}
		} else {
			expectedSeq++
		}
	}

	if len(report.Breaks) > 0 {
		first := report.Breaks[0]
		report.FirstBreakSeq = first.Seq
		report.FirstBreakID = first.ID
		report.FirstBreakReason = first.Reason
	} else {
		report.Intact = true
	}

	last := logs[len(logs)-1]
	if last.Seq != nil {
		report.LastSeq = *last.Seq
	}
	if last.Fingerprint != "" {
		report.LastFingerprint = last.Fingerprint
	}
	return report, nil
}

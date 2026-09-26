package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
	"gorm.io/gorm"
)

// appendMu serializes chain-tip reads and chained inserts. Each deployment
// runs a single backend replica behind the Compose service, so a process
// lock is sufficient and keeps the semantics portable across MySQL,
// PostgreSQL and SQLite (which lacks SELECT ... FOR UPDATE).
var appendMu sync.Mutex

// AppendChainedAudit seals log with the next chain position and fingerprint,
// then inserts it inside one transaction.
func (r *securityRepository) AppendChainedAudit(ctx context.Context, log *model.AuditLog) error {
	appendMu.Lock()
	defer appendMu.Unlock()

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Freeze timestamp precision before sealing so the value read back
		// from MySQL DATETIME / SQLite reproduces the same fingerprint.
		if log.CreatedAt.IsZero() {
			log.CreatedAt = time.Now().UTC()
		}
		log.CreatedAt = log.CreatedAt.UTC().Truncate(time.Millisecond)
		var tip model.AuditLog
		err := tx.Order("seq DESC, id DESC").First(&tip).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			seq := uint(1)
			log.Seq = &seq
			log.PrevFingerprint = model.GenesisFingerprint
		case err != nil:
			return err
		default:
			seq := *tip.Seq + 1
			log.Seq = &seq
			log.PrevFingerprint = tip.Fingerprint
		}
		log.Fingerprint = model.ComputeAuditFingerprint(*log)
		return tx.Create(log).Error
	})
}

// ListAuditsChain returns every audit record in chain order (oldest first).
func (r *securityRepository) ListAuditsChain(ctx context.Context) ([]model.AuditLog, error) {
	logs := make([]model.AuditLog, 0)
	err := r.db.WithContext(ctx).
		Order("COALESCE(seq, id) ASC, id ASC").Find(&logs).Error
	return logs, err
}

// BackfillAuditChain seals audit rows created before fingerprinting existed.
// It is a startup migration:
//   - when no row is sealed yet (fresh pre-chain data), the whole table is
//     sealed from the genesis fingerprint;
//   - when a sealed tail exists, only the unsealed head is continued from it,
//     so the routine is idempotent and safe to run on every boot.
func (r *securityRepository) BackfillAuditChain(ctx context.Context) error {
	appendMu.Lock()
	defer appendMu.Unlock()

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var unsealedCount int64
		if err := tx.Model(&model.AuditLog{}).
			Where("seq IS NULL OR fingerprint = ''").Count(&unsealedCount).Error; err != nil {
			return err
		}
		if unsealedCount == 0 {
			return nil
		}

		var sealedCount int64
		if err := tx.Model(&model.AuditLog{}).
			Where("seq IS NOT NULL AND fingerprint <> ''").Count(&sealedCount).Error; err != nil {
			return err
		}

		prev := model.GenesisFingerprint
		nextSeq := uint(1)
		if sealedCount > 0 {
			var tip model.AuditLog
			if err := tx.Where("seq IS NOT NULL").
				Order("seq DESC, id DESC").First(&tip).Error; err != nil {
				return err
			}
			prev = tip.Fingerprint
			nextSeq = *tip.Seq + 1
		}

		pending := make([]model.AuditLog, 0, unsealedCount)
		if err := tx.Where("seq IS NULL OR fingerprint = ''").
			Order("id ASC").Find(&pending).Error; err != nil {
			return err
		}
		for i := range pending {
			pending[i].CreatedAt = pending[i].CreatedAt.UTC().Truncate(time.Millisecond)
			seq := nextSeq + uint(i)
			pending[i].Seq = &seq
			pending[i].PrevFingerprint = prev
			pending[i].Fingerprint = model.ComputeAuditFingerprint(pending[i])
			prev = pending[i].Fingerprint
			if err := tx.Model(&model.AuditLog{}).Where("id = ?", pending[i].ID).
				Updates(map[string]any{
					"seq":              seq,
					"prev_fingerprint": pending[i].PrevFingerprint,
					"fingerprint":      pending[i].Fingerprint,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

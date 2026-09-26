package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
	"gorm.io/gorm"
)

// ErrAuditChainRace 表示两个请求并发抢占同一链序号，调用方应重试整个事务。
var ErrAuditChainRace = errors.New("audit chain sequence contention")

const auditChainMaxAttempts = 12

// AppendAuditChain 在一个事务里把新审计记录接到指纹链尾，并同步更新链尾锚点。
// 并发请求即使前后脚到达，也依靠 seq 唯一索引串行化：抢到该序号的事务提交，
// 其余事务拿到唯一约束冲突后重新读取链尾并重试。
func (r *securityRepository) AppendAuditChain(ctx context.Context, log *model.AuditLog) error {
	var lastErr error
	for attempt := 0; attempt < auditChainMaxAttempts; attempt++ {
		// 每次尝试使用新副本：失败的 INSERT 可能已给指针回填自增主键，
		// 重试时复用会造成主键冲突。
		candidate := *log
		lastErr = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			anchor, err := lockAuditAnchor(tx)
			if err != nil {
				return err
			}
			nextSeq := anchor.LastSeq + 1
			candidate.CreatedAt = candidate.CreatedAt.UTC().Truncate(time.Millisecond)
			candidate.Seq = &nextSeq
			candidate.PrevFingerprint = anchor.LastFingerprint
			if anchor.LastSeq == 0 {
				candidate.PrevFingerprint = model.AuditGenesisFingerprint
			}
			candidate.Fingerprint = model.ComputeAuditFingerprint(nextSeq, candidate.PrevFingerprint, candidate)
			if err := tx.Create(&candidate).Error; err != nil {
				if isChainRetryableError(err) {
					return ErrAuditChainRace
				}
				return err
			}
			anchor.LastSeq = nextSeq
			anchor.LastFingerprint = candidate.Fingerprint
			anchor.UpdatedAt = time.Now().UTC()
			result := tx.Save(&anchor)
			if result.Error != nil {
				if isChainRetryableError(result.Error) {
					return ErrAuditChainRace
				}
				return result.Error
			}
			if result.RowsAffected == 0 {
				return ErrAuditChainRace
			}
			return nil
		})
		if lastErr == nil {
			*log = candidate
			return nil
		}
		if !errors.Is(lastErr, ErrAuditChainRace) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Millisecond):
		}
	}
	return lastErr
}

// lockAuditAnchor 读取单行锚点；锚点不存在（首次启动）时初始化创世行。
// MySQL/PostgreSQL 下通过主键单行写获得间隙锁/行锁即可串行化同序号竞争，
// SQLite 写事务本身全库串行，因此这里不使用 FOR UPDATE（SQLite 不支持）。
func lockAuditAnchor(tx *gorm.DB) (model.AuditChainAnchor, error) {
	var anchor model.AuditChainAnchor
	err := tx.Where("id = ?", 1).First(&anchor).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		anchor = model.AuditChainAnchor{
			ID: 1, LastSeq: 0, LastFingerprint: model.AuditGenesisFingerprint,
			UpdatedAt: time.Now().UTC(),
		}
		if err := tx.Create(&anchor).Error; err != nil {
			if isUniqueConstraintError(err) {
				if retryErr := tx.Where("id = ?", 1).First(&anchor).Error; retryErr != nil {
					return model.AuditChainAnchor{}, retryErr
				}
				return anchor, nil
			}
			return model.AuditChainAnchor{}, err
		}
		return anchor, nil
	}
	if err != nil {
		return model.AuditChainAnchor{}, err
	}
	return anchor, nil
}

// ListAuditsInChainOrder 按链顺序返回全部审计记录，供链校验使用。
// 未入链的历史记录（seq 为空）排在最后单独标识。
func (r *securityRepository) ListAuditsInChainOrder(ctx context.Context) ([]model.AuditLog, error) {
	logs := make([]model.AuditLog, 0)
	err := r.db.WithContext(ctx).
		Order("CASE WHEN seq IS NULL THEN 1 ELSE 0 END ASC, seq ASC, id ASC").
		Find(&logs).Error
	return logs, err
}

func (r *securityRepository) GetAuditChainAnchor(ctx context.Context) (model.AuditChainAnchor, error) {
	var anchor model.AuditChainAnchor
	err := r.db.WithContext(ctx).Where("id = ?", 1).First(&anchor).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.AuditChainAnchor{LastFingerprint: model.AuditGenesisFingerprint}, nil
	}
	return anchor, err
}

// EnsureAuditChain 在启动迁移后回填历史审计记录：按 ID 顺序为还没有链序号
// 的记录补算序号和指纹，并（在锚点缺失时）写入链尾锚点。已入链的记录不动，
// 因此服务重启或并发启动都不会重写既有指纹。
func (r *securityRepository) EnsureAuditChain(ctx context.Context) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		anchor, err := lockAuditAnchor(tx)
		if err != nil {
			return err
		}
		var pending []model.AuditLog
		if err := tx.Where("seq IS NULL").Order("id ASC").Find(&pending).Error; err != nil {
			return err
		}
		for i := range pending {
			log := pending[i]
			nextSeq := anchor.LastSeq + 1
			log.CreatedAt = log.CreatedAt.UTC().Truncate(time.Millisecond)
			prev := anchor.LastFingerprint
			if anchor.LastSeq == 0 {
				prev = model.AuditGenesisFingerprint
			}
			fingerprint := model.ComputeAuditFingerprint(nextSeq, prev, log)
			if err := tx.Model(&model.AuditLog{}).Where("id = ?", log.ID).
				Updates(map[string]any{
					"seq": nextSeq, "prev_fingerprint": prev, "fingerprint": fingerprint,
					"created_at": log.CreatedAt,
				}).Error; err != nil {
				return err
			}
			anchor.LastSeq = nextSeq
			anchor.LastFingerprint = fingerprint
		}
		if len(pending) > 0 {
			anchor.UpdatedAt = time.Now().UTC()
			if err := tx.Save(&anchor).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// isChainRetryableError 识别需要整事务重试的并发问题：序号唯一冲突、
// 死锁、锁等待超时，以及 SQLite 的 database is locked。
func isChainRetryableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	if isUniqueConstraintError(err) {
		return true
	}
	return strings.Contains(message, "deadlock") ||
		strings.Contains(message, "lock wait timeout") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "1213") ||
		strings.Contains(message, "1205") ||
		strings.Contains(message, "40001") ||
		strings.Contains(message, "55006") ||
		strings.Contains(message, "55p03")
}

// isUniqueConstraintError 识别 MySQL / PostgreSQL / SQLite 的唯一约束冲突。
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate") ||
		strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "unique violation") ||
		strings.Contains(message, "1062") ||
		strings.Contains(message, "23505") ||
		strings.Contains(message, "constraint failed")
}

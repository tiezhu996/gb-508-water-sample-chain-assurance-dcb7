package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

// AuditGenesisFingerprint 是指纹链的创世“前指纹”，第一条记录以它为根。
const AuditGenesisFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

// auditFingerprintPayload 定义参与指纹计算的字段顺序与内容。
// 只纳入业务字段和链序号，不包含 ID / PrevFingerprint / Fingerprint 本身；
// 加入 Seq 可以发现“整行替换”和中间插入伪造记录。
type auditFingerprintPayload struct {
	Seq         uint64 `json:"seq"`
	RequestID   string `json:"requestId"`
	Actor       string `json:"actor"`
	Action      string `json:"action"`
	EntityType  string `json:"entityType"`
	EntityID    uint   `json:"entityId"`
	BeforeState string `json:"beforeState"`
	AfterState  string `json:"afterState"`
	Detail      string `json:"detail"`
	CreatedAt   string `json:"createdAt"`
}

// AuditFingerprintCanonicalTime 将时间规整为毫秒精度的 UTC 文本。
// MySQL datetime(3) / SQLite / PostgreSQL 都能稳定到毫秒，避免存储
// 截断导致写入时与校验时算出的指纹不一致。
func AuditFingerprintCanonicalAt(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// ComputeAuditFingerprint 按上一条指纹和本条内容计算 SHA-256 指纹。
func ComputeAuditFingerprint(seq uint64, prevFingerprint string, log AuditLog) string {
	payload := auditFingerprintPayload{
		Seq:         seq,
		RequestID:   log.RequestID,
		Actor:       log.Actor,
		Action:      log.Action,
		EntityType:  log.EntityType,
		EntityID:    log.EntityID,
		BeforeState: log.BeforeState,
		AfterState:  log.AfterState,
		Detail:      log.Detail,
		CreatedAt:   AuditFingerprintCanonicalAt(log.CreatedAt),
	}
	body, _ := json.Marshal(payload)
	sum := sha256.Sum256([]byte(prevFingerprint + "\n" + string(body)))
	return hex.EncodeToString(sum[:])
}

// ParseAuditSeq 用于测试和校验时把可空序号转为数值。
func ParseAuditSeq(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

// FormatAuditSeq 供错误信息使用。
func FormatAuditSeq(seq uint64) string {
	return strconv.FormatUint(seq, 10)
}

package model

import "time"

type User struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Username     string    `json:"username" gorm:"size:80;uniqueIndex;not null"`
	DisplayName  string    `json:"displayName" gorm:"size:120;not null"`
	PasswordHash string    `json:"-" gorm:"size:120;not null"`
	Role         string    `json:"role" gorm:"size:32;index;not null"`
	Active       bool      `json:"active" gorm:"not null;default:true"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AuditLog 是审计指纹链上的一个环节。Seq 从 1 开始连续编号，
// PrevFingerprint 指向上一条记录的 Fingerprint，任何对既有内容的
// 改动或记录缺失都会在链校验中暴露。
type AuditLog struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Seq             *uint64   `json:"seq" gorm:"uniqueIndex"`
	PrevFingerprint string    `json:"prevFingerprint" gorm:"size:64"`
	Fingerprint     string    `json:"fingerprint" gorm:"size:64"`
	RequestID       string    `json:"requestId" gorm:"size:64;index"`
	Actor           string    `json:"actor" gorm:"size:80;index"`
	Action          string    `json:"action" gorm:"size:80;index"`
	EntityType      string    `json:"entityType" gorm:"size:80;index"`
	EntityID        uint      `json:"entityId" gorm:"index"`
	BeforeState     string    `json:"beforeState" gorm:"size:40"`
	AfterState      string    `json:"afterState" gorm:"size:40"`
	Detail          string    `json:"detail" gorm:"size:2000"`
	CreatedAt       time.Time `json:"createdAt" gorm:"index"`
}

// AuditChainAnchor 记录链尾状态，用来发现“末尾记录被整段删除”的情况：
// 单纯校验相邻指纹无法察觉尾部缺失，因此追加记录时在同一事务里更新锚点。
type AuditChainAnchor struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	LastSeq         uint64    `json:"lastSeq"`
	LastFingerprint string    `json:"lastFingerprint" gorm:"size:64"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type AuditActionCount struct {
	Action string `json:"action" gorm:"column:action"`
	Count  int64  `json:"count" gorm:"column:count"`
}

type AuditEntityCount struct {
	EntityType string `json:"entityType" gorm:"column:entity_type"`
	Count      int64  `json:"count" gorm:"column:count"`
}

type AuditSummary struct {
	Since        time.Time          `json:"since"`
	Total        int64              `json:"total"`
	Transitions  int64              `json:"transitions"`
	UniqueActors int64              `json:"uniqueActors"`
	Actions      []AuditActionCount `json:"actions"`
	EntityTypes  []AuditEntityCount `json:"entityTypes"`
}

// AuditChainIssueKind 标识链校验发现的异常类型。
const (
	AuditChainIssueUnchained  = "unchained"   // 记录没有进入指纹链（历史数据未回填）
	AuditChainIssueMissing    = "missing"     // 该序号应有记录但缺失（被删除）
	AuditChainIssueBrokenLink = "broken_link" // 上一条指纹对不上
	AuditChainIssueTampered   = "tampered"    // 内容重算指纹与存储指纹不一致
	AuditChainIssueAnchor     = "anchor"      // 链尾锚点与实际链尾不一致
)

// AuditChainIssue 指向链上第一个（以及前若干个）对不上的环节。
type AuditChainIssue struct {
	Kind     string `json:"kind"`
	Seq      uint64 `json:"seq,omitempty"`
	LogID    uint   `json:"logId,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// AuditChainStatus 是审计页链完整性结论。Intact 为 false 时 FirstIssue
// 指向从哪一条开始对不上，Issues 给出最多若干个可定位的异常环节。
type AuditChainStatus struct {
	Intact           bool              `json:"intact"`
	Total            int64             `json:"total"`
	VerifiedCount    int               `json:"verifiedCount"`
	LastSeq          uint64            `json:"lastSeq"`
	GenesisHash      string            `json:"genesisHash"`
	AnchorConsistent bool              `json:"anchorConsistent"`
	FirstIssue       *AuditChainIssue  `json:"firstIssue,omitempty"`
	Issues           []AuditChainIssue `json:"issues"`
}

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleReviewer = "reviewer"
	RoleAdmin    = "admin"
)

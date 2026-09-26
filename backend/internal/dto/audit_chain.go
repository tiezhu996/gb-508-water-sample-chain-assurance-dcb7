package dto

import "github.com/blueship581/water-sample-chain-assurance/backend/internal/model"

// AuditChainEntry 是审计列表里的一条记录，附带它在指纹链上的校验结论，
// 链对不上时前端仍能照往常一样翻看每条记录。
type AuditChainEntry struct {
	model.AuditLog
	ChainOK bool   `json:"chainOk"`
	Issue   string `json:"issue,omitempty"`
}

package service

import (
	"context"
	"fmt"

	"github.com/blueship581/water-sample-chain-assurance/backend/internal/model"
)

// auditChainIssueLimit 限制返回的异常环节数量，异常行很多时页面只展示前若干个，
// FirstIssue 始终指向第一个对不上的位置。
const auditChainIssueLimit = 50

// AuditChainStatus 从头按序号逐条重算指纹：内容被改过会暴露为 tampered，
// 上一条指纹对不上暴露为 broken_link，序号有空洞暴露为 missing（被删除），
// 链尾锚点对不上则暴露为 anchor（通常是末尾记录被整段删除或锚点被改）。
func (s *securityService) AuditChainStatus(ctx context.Context) (model.AuditChainStatus, error) {
	logs, err := s.repository.ListAuditsInChainOrder(ctx)
	if err != nil {
		return model.AuditChainStatus{}, err
	}
	anchor, err := s.repository.GetAuditChainAnchor(ctx)
	if err != nil {
		return model.AuditChainStatus{}, err
	}

	status := model.AuditChainStatus{
		Total:            int64(len(logs)),
		Issues:           make([]model.AuditChainIssue, 0),
		AnchorConsistent: true,
	}
	bySeq := make(map[uint64]model.AuditLog, len(logs))
	chainedCount := 0
	for _, log := range logs {
		if log.Seq != nil {
			bySeq[*log.Seq] = log
			chainedCount++
		}
	}
	if chainedCount > 0 {
		if genesis, ok := bySeq[1]; ok {
			status.GenesisHash = genesis.Fingerprint
		}
	}

	addIssue := func(issue model.AuditChainIssue) {
		if len(status.Issues) < auditChainIssueLimit {
			status.Issues = append(status.Issues, issue)
		}
	}

	expectedSeq := uint64(1)
	prevFingerprint := model.AuditGenesisFingerprint
	verified := 0
	for _, log := range logs {
		if log.Seq == nil {
			continue
		}
		// 当前记录之前出现的序号空洞（记录被删除）。
		for expectedSeq < *log.Seq && len(status.Issues) < auditChainIssueLimit {
			addIssue(model.AuditChainIssue{
				Kind:   model.AuditChainIssueMissing,
				Seq:    expectedSeq,
				Detail: fmt.Sprintf("第 %d 条审计记录缺失（链上应为连续序号）", expectedSeq),
			})
			expectedSeq++
		}
		seq := *log.Seq
		expectedSeq = seq + 1

		contentFingerprint := model.ComputeAuditFingerprint(seq, log.PrevFingerprint, log)
		contentOK := contentFingerprint == log.Fingerprint
		linkOK := log.PrevFingerprint == prevFingerprint
		if !linkOK {
			addIssue(model.AuditChainIssue{
				Kind:     model.AuditChainIssueBrokenLink,
				Seq:      seq,
				LogID:    log.ID,
				Expected: prevFingerprint,
				Actual:   log.PrevFingerprint,
				Detail:   fmt.Sprintf("第 %d 条记录的前指纹与上一条指纹不一致，链从此处断开", seq),
			})
		}
		if !contentOK {
			addIssue(model.AuditChainIssue{
				Kind:     model.AuditChainIssueTampered,
				Seq:      seq,
				LogID:    log.ID,
				Expected: contentFingerprint,
				Actual:   log.Fingerprint,
				Detail:   fmt.Sprintf("第 %d 条记录内容被修改或指纹被替换，重算结果与存储指纹不一致", seq),
			})
		}
		if contentOK && linkOK {
			verified++
			prevFingerprint = log.Fingerprint
		} else if contentOK {
			// 内容本身没改，但链已断：继续用这条自身的指纹作为后续比较基准，
			// 避免断链点之后每条都报重复异常。
			prevFingerprint = log.Fingerprint
		}
	}
	// 末尾整段删除：锚点记得的序号超过现存最大序号。
	for expectedSeq <= anchor.LastSeq && len(status.Issues) < auditChainIssueLimit {
		addIssue(model.AuditChainIssue{
			Kind:   model.AuditChainIssueMissing,
			Seq:    expectedSeq,
			Detail: fmt.Sprintf("第 %d 条及之后的审计记录缺失（链尾锚点显示应有记录）", expectedSeq),
		})
		expectedSeq++
	}

	// 未入链的历史记录（启动回填后正常不应出现）。
	for _, log := range logs {
		if log.Seq == nil && len(status.Issues) < auditChainIssueLimit {
			addIssue(model.AuditChainIssue{
				Kind:   model.AuditChainIssueUnchained,
				LogID:  log.ID,
				Detail: fmt.Sprintf("数据库记录 ID=%d 未进入指纹链", log.ID),
			})
		}
	}

	// 锚点一致性：锚点记录的链尾必须与实际链尾吻合，防止“删了末尾若干条”。
	var maxSeq uint64
	for seq := range bySeq {
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	switch {
	case chainedCount == 0 && anchor.LastSeq != 0:
		status.AnchorConsistent = false
		addIssue(model.AuditChainIssue{
			Kind:   model.AuditChainIssueAnchor,
			Seq:    anchor.LastSeq,
			Detail: "链尾锚点显示存在审计记录，但链上没有任何记录，末尾记录可能被删除",
		})
	case chainedCount > 0 && anchor.LastSeq != maxSeq:
		status.AnchorConsistent = false
		addIssue(model.AuditChainIssue{
			Kind:     model.AuditChainIssueAnchor,
			Seq:      anchor.LastSeq,
			Expected: fmt.Sprintf("lastSeq=%d", maxSeq),
			Actual:   fmt.Sprintf("lastSeq=%d", anchor.LastSeq),
			Detail:   fmt.Sprintf("链尾锚点序号为 %d，实际链尾序号为 %d，末尾记录可能被删除", anchor.LastSeq, maxSeq),
		})
	case chainedCount > 0:
		if tail, ok := bySeq[anchor.LastSeq]; ok && tail.Fingerprint != anchor.LastFingerprint {
			status.AnchorConsistent = false
			addIssue(model.AuditChainIssue{
				Kind:     model.AuditChainIssueAnchor,
				Seq:      anchor.LastSeq,
				Expected: tail.Fingerprint,
				Actual:   anchor.LastFingerprint,
				Detail:   "链尾锚点指纹与最后一条记录的指纹不一致，链尾记录或锚点被改动",
			})
		}
	}

	status.VerifiedCount = verified
	status.LastSeq = maxSeq
	if len(status.Issues) > 0 {
		first := status.Issues[0]
		status.FirstIssue = &first
		status.Intact = false
	} else {
		status.Intact = true
	}
	return status, nil
}

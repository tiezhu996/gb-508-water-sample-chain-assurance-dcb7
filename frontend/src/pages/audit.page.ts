import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { getAuditChain, listAudits } from '../api/audit';
import type { AuditChainEntry, AuditChainIssue, AuditChainStatus } from '../types/domain';
import { formatDate } from '../utils/format';

const ISSUE_LABELS: Record<string, string> = {
  tampered: '内容被改动',
  broken_link: '指纹接不上',
  missing: '记录缺失',
  unchained: '未入链',
  anchor: '链尾锚点不符',
};

const PAGE_SIZE = 30;

@Component({
  selector: 'app-audit-page',
  standalone: true,
  imports: [CommonModule],
  template: `
  <main class="workspace">
    <header class="page-header">
      <div>
        <p class="eyebrow">治理与追踪</p>
        <h1>操作审计</h1>
        <p>每条审计记录都按上一条指纹和本条内容计算指纹，前后相扣成链；改动或缺失都会被指出来。</p>
      </div>
    </header>

    <div *ngIf="error" class="alert">{{ error }}</div>

    <section class="chain-banner" *ngIf="chain" [class.chain-banner--broken]="!chain.intact">
      <div class="chain-headline">
        <span class="status" [class.status--success]="chain.intact" [class.status--danger]="!chain.intact">
          {{ chain.intact ? '链完整' : '链对不上' }}
        </span>
        <strong>{{ chain.lastSeq }} 条记录 · 校验通过 {{ chain.verifiedCount }} 条</strong>
        <small *ngIf="chain.genesisHash">创世指纹 <code>{{ shortHash(chain.genesisHash) }}</code></small>
      </div>
      <div class="chain-diagnosis" *ngIf="!chain.intact && chain.firstIssue as first">
        <p>
          从第 <strong>{{ first.seq || '?' }}</strong> 条开始对不上：
          <strong>{{ issueLabel(first.kind) }}</strong>
          <span *ngIf="first.detail">— {{ first.detail }}</span>
        </p>
        <ul class="chain-issues">
          <li *ngFor="let issue of chain.issues">
            <span class="status status--danger">{{ issueLabel(issue.kind) }}</span>
            <ng-container *ngIf="issue.seq">第 {{ issue.seq }} 条</ng-container>
            <ng-container *ngIf="issue.logId">记录 ID {{ issue.logId }}</ng-container>
            <small *ngIf="issue.detail">{{ issue.detail }}</small>
          </li>
        </ul>
      </div>
      <div class="chain-diagnosis" *ngIf="chain.intact">
        <p>所有记录按顺序逐一对上，未发现改动或缺条。</p>
      </div>
    </section>

    <section class="audit-list">
      <article *ngFor="let log of logs" [class.audit-row--broken]="!log.chainOk">
        <time>{{ formatDate(log.createdAt) }}</time>
        <div>
          <strong>{{ log.actor }} · {{ log.action }}</strong>
          <small class="audit-seq">#{{ log.seq ?? '未入链' }}</small>
        </div>
        <span>{{ log.entityType }} #{{ log.entityId }}</span>
        <code>{{ log.beforeState || '-' }} → {{ log.afterState || '-' }}</code>
        <div class="audit-chain-cell">
          <small>{{ log.requestId }}</small>
          <small class="audit-fp">指纹 {{ shortHash(log.fingerprint) }}</small>
          <span *ngIf="!log.chainOk" class="status status--danger">{{ issueLabel(log.issue || '') }}</span>
        </div>
      </article>
      <div *ngIf="!logs.length && !error" class="empty">暂无审计记录</div>
    </section>

    <footer class="audit-pager">
      <button class="link-button" [disabled]="page <= 1" (click)="changePage(page - 1)">上一页</button>
      <small>第 {{ page }} 页 · 共 {{ total }} 条</small>
      <button class="link-button" [disabled]="page * pageSize >= total" (click)="changePage(page + 1)">下一页</button>
    </footer>
  </main>`,
})
export class AuditPage implements OnInit {
  logs: AuditChainEntry[] = [];
  chain: AuditChainStatus | null = null;
  error = '';
  page = 1;
  pageSize = PAGE_SIZE;
  total = 0;
  readonly formatDate = formatDate;

  constructor(private readonly changeDetector: ChangeDetectorRef) {}

  async ngOnInit() {
    await this.load();
  }

  async changePage(page: number) {
    this.page = page;
    await this.load();
  }

  async load() {
    this.error = '';
    try {
      const [list, chain] = await Promise.all([
        listAudits(this.page, this.pageSize),
        getAuditChain(),
      ]);
      this.logs = list.data;
      this.total = list.meta?.total ?? 0;
      this.chain = chain.data;
    } catch (reason) {
      this.error = String(reason);
    } finally {
      this.changeDetector.detectChanges();
    }
  }

  shortHash(value: string): string {
    return value ? value.slice(0, 12) : '-';
  }

  issueLabel(kind: string): string {
    return ISSUE_LABELS[kind] || kind || '链异常';
  }
}

import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { getAuditChain, listAudits } from '../api/audit';
import type { AuditBreakReason, AuditChainReport, AuditChainBreak, AuditLog } from '../types/domain';
import { formatDate } from '../utils/format';

const PAGE_SIZE = 30;

const REASON_LABEL: Record<AuditBreakReason, { text: string; tone: string }> = {
  legacy: { text: '历史记录（指纹功能启用前）', tone: 'neutral' },
  gap: { text: '疑似缺失记录', tone: 'danger' },
  tampered: { text: '内容被篡改', tone: 'danger' },
  brokenLink: { text: '与上一条指纹对不上', tone: 'danger' },
};

@Component({
  selector: 'app-audit-page',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <main class="workspace">
    <header class="page-header">
      <div>
        <p class="eyebrow">治理与追踪</p>
        <h1>操作审计</h1>
        <p>每条记录按上一条指纹与本条内容链式封印；记录被改、被删都会在此暴露，链路异常时记录仍可照常翻阅。</p>
      </div>
      <button class="link-button" type="button" (click)="reload()">重新校验</button>
    </header>

    <div *ngIf="error" class="alert">{{ error }}</div>

    <section class="chain-panel" [class.chain-panel--broken]="chain && !chain.intact" [class.chain-panel--ok]="chain?.intact">
      <header>
        <div>
          <span class="chain-verdict" [class.status--success]="chain?.intact" [class.status--danger]="chain && !chain.intact">
            {{ chain ? (chain.intact ? '指纹链完整' : '指纹链异常') : '校验中…' }}
          </span>
          <ng-container *ngIf="chain && !chain.intact">
            <strong class="chain-first-break">
              从第 {{ chain.firstBreakSeq || '?' }} 条开始对不上
              <small>（记录 ID #{{ chain.firstBreakId }} · {{ reasonText(chain.firstBreakReason) }}）</small>
            </strong>
          </ng-container>
        </div>
        <small *ngIf="chain" class="chain-tip">
          {{ chain.intact ? '全部记录均通过内容与链接双重校验' : '下方红标记录及其之后需逐条复核；记录本身仍可正常查看' }}
        </small>
      </header>
      <div class="chain-stats" *ngIf="chain">
        <article><span>链上记录总数</span><strong>{{ chain.total }}</strong></article>
        <article><span>校验通过</span><strong>{{ chain.verified }}</strong></article>
        <article><span>异常记录</span><strong [class.chain-danger-text]="chain.breaks.length">{{ chain.breaks.length }}</strong></article>
        <article *ngIf="chain.legacy"><span>历史未封印</span><strong>{{ chain.legacy }}</strong></article>
        <article><span>最新链位</span><strong>#{{ chain.lastSeq || 0 }}</strong></article>
      </div>
    </section>

    <section class="toolbar">
      <input type="search" placeholder="按操作者、实体类型或动作搜索" [(ngModel)]="search" (keyup.enter)="applySearch()" />
      <button class="table-action" type="button" (click)="applySearch()">搜索</button>
      <button class="table-action" type="button" (click)="resetSearch()">重置</button>
      <span class="muted" style="align-self:center">共 {{ total }} 条</span>
    </section>

    <section class="table-shell">
      <p *ngIf="loading" class="empty">正在加载审计记录…</p>
      <div *ngIf="!loading && !logs.length" class="empty">暂无审计记录</div>
      <div class="audit-list">
        <article *ngFor="let log of logs" [class.audit-row--broken]="breakOf(log)">
          <div class="audit-seq">
            <span class="seq-badge">#{{ log.seq ?? '—' }}</span>
            <span *ngIf="breakOf(log)" class="status status--danger chain-flag">{{ reasonText(breakOf(log)?.reason) }}</span>
            <span *ngIf="!breakOf(log) && log.fingerprint" class="status status--success chain-flag">已校验</span>
          </div>
          <time>{{ formatDate(log.createdAt) }}</time>
          <strong>{{ log.actor }} · {{ log.action }}</strong>
          <span>{{ log.entityType }} #{{ log.entityId }}</span>
          <code>{{ log.beforeState || '-' }} → {{ log.afterState || '-' }}</code>
          <div class="audit-meta">
            <small>{{ log.requestId }}</small>
            <small *ngIf="log.detail">{{ log.detail }}</small>
          </div>
        </article>
      </div>
    </section>

    <footer class="audit-pager" *ngIf="total > pageSize">
      <button class="table-action" type="button" [disabled]="page === 1" (click)="changePage(page - 1)">上一页</button>
      <span class="muted">第 {{ page }} / {{ totalPages }} 页</span>
      <button class="table-action" type="button" [disabled]="page >= totalPages" (click)="changePage(page + 1)">下一页</button>
    </footer>
  </main>
  `,
})
export class AuditPage implements OnInit {
  logs: AuditLog[] = [];
  chain: AuditChainReport | null = null;
  breakBySeq = new Map<number, AuditChainBreak>();
  error = '';
  loading = true;
  search = '';
  page = 1;
  total = 0;
  readonly pageSize = PAGE_SIZE;

  constructor(private readonly changeDetector: ChangeDetectorRef) {}

  async ngOnInit(): Promise<void> {
    await this.reload();
  }

  async reload(): Promise<void> {
    this.loading = true;
    this.error = '';
    try {
      const [listResult, chainResult] = await Promise.all([
        listAudits(this.page, this.pageSize, this.search.trim()),
        getAuditChain(),
      ]);
      this.logs = listResult.data ?? [];
      this.total = listResult.meta?.total ?? this.logs.length;
      this.chain = chainResult.data ?? null;
      this.breakBySeq = new Map((this.chain?.breaks ?? []).map((item) => [item.seq, item]));
    } catch (reason) {
      this.error = `加载审计信息失败：${String(reason)}`;
    } finally {
      this.loading = false;
      this.changeDetector.detectChanges();
    }
  }

  breakOf(log: AuditLog): AuditChainBreak | undefined {
    return log.seq != null ? this.breakBySeq.get(log.seq) : undefined;
  }

  reasonText(reason?: AuditBreakReason): string {
    return reason ? REASON_LABEL[reason]?.text ?? reason : '未知异常';
  }

  get totalPages(): number {
    return Math.max(1, Math.ceil(this.total / this.pageSize));
  }

  async applySearch(): Promise<void> {
    this.page = 1;
    await this.loadPage();
  }

  async resetSearch(): Promise<void> {
    this.search = '';
    this.page = 1;
    await this.loadPage();
  }

  async changePage(page: number): Promise<void> {
    this.page = page;
    await this.loadPage();
  }

  private async loadPage(): Promise<void> {
    this.loading = true;
    try {
      const result = await listAudits(this.page, this.pageSize, this.search.trim());
      this.logs = result.data ?? [];
      this.total = result.meta?.total ?? this.logs.length;
    } catch (reason) {
      this.error = `加载审计记录失败：${String(reason)}`;
    } finally {
      this.loading = false;
      this.changeDetector.detectChanges();
    }
  }
}

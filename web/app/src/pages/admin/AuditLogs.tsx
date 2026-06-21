import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input, Select } from '@/components/form'
import { Pagination } from '@/components/Pagination'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

interface AuditLog {
  id: string
  operatorId: string
  operatorName: string
  operatorRole: string
  action: string
  entityType: string
  entityId: string
  entityName: string
  beforeState: string
  afterState: string
  createdAt: string
}

interface AuditLogsResponse {
  logs: AuditLog[]
  total: number
  page: number
  pages: number
  pageSize: number
  pageSizeOpts: number[]
  rollbackDays: number
  filters: {
    q: string
    entityType: string
    action: string
    operatorId: string
    from: string
    to: string
  }
}

const ACTION_LABELS: Record<string, string> = {
  create: '创建',
  update: '更新',
  delete: '删除',
}

const ENTITY_LABELS: Record<string, string> = {
  user: '用户',
  group: '分组',
  role: '角色',
  provider: '登录方式',
  client: '应用',
  project: '项目',
  setting: '设置',
  announcement: '公告',
}

function actionLabel(a: string) {
  return ACTION_LABELS[a] ?? a
}
function entityLabel(e: string) {
  return ENTITY_LABELS[e] ?? e
}

export default function AuditLogs() {
  const [params, setParams] = useSearchParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  // ── Filter state lives in the URL ──────────────────────────────────────────
  const urlQ = params.get('q') ?? ''
  const operatorId = params.get('operator_id') ?? ''
  const entityType = params.get('entity_type') ?? ''
  const action = params.get('action') ?? ''
  const from = params.get('from') ?? ''
  const to = params.get('to') ?? ''
  const pageSize = params.get('page_size') ?? ''
  const page = Math.max(1, parseInt(params.get('page') ?? '1', 10) || 1)

  // Local search box; pushed into URL on submit (no debounce needed here).
  const [search, setSearch] = useState(urlQ)
  useEffect(() => {
    setSearch(urlQ)
  }, [urlQ])

  // setParam updates one filter and resets the page (except when setting page).
  function setParam(key: string, value: string | number | null) {
    setParams((prev) => {
      const next = new URLSearchParams(prev)
      if (value === null || value === '') next.delete(key)
      else next.set(key, String(value))
      if (key !== 'page') next.delete('page')
      return next
    })
  }

  // ── Query (URL-derived key so each combination is cached) ───────────────────
  const filters = { q: urlQ, operatorId, entityType, action, from, to, page_size: pageSize, page }
  const queryString = (() => {
    const sp = new URLSearchParams()
    if (urlQ) sp.set('q', urlQ)
    if (operatorId) sp.set('operator_id', operatorId)
    if (entityType) sp.set('entity_type', entityType)
    if (action) sp.set('action', action)
    if (from) sp.set('from', from)
    if (to) sp.set('to', to)
    if (pageSize) sp.set('page_size', pageSize)
    if (page > 1) sp.set('page', String(page))
    return sp.toString()
  })()

  const { data, isLoading, isFetching, isError } = useQuery({
    queryKey: qk.auditLogs(filters),
    queryFn: () => api.get<AuditLogsResponse>('/admin/audit-logs?' + queryString),
    placeholderData: keepPreviousData,
  })

  const rollbackDays = data?.rollbackDays ?? 3

  const rollback = useMutation({
    mutationFn: (id: string) => api.post('/admin/audit-logs/' + id + '/rollback'),
    onSuccess: (res) => {
      toast(res.flash || '回滚成功', 'success')
      qc.invalidateQueries({ queryKey: ['admin', 'audit'] })
    },
    onError: (err) => {
      toast(err instanceof ApiError ? err.message : '回滚失败', 'error')
    },
  })

  async function askRollback(log: AuditLog) {
    const ok = await confirm({
      title: '回滚操作',
      message: `确定要回滚这条「${actionLabel(log.action)}${entityLabel(log.entityType)}」记录吗？`,
      confirmLabel: '回滚',
      danger: true,
    })
    if (ok) rollback.mutate(log.id)
  }

  // A row is rollback-able if it has a before-state to restore and falls within
  // the server-enforced window (createdAt within rollbackDays).
  function canRollback(log: AuditLog): boolean {
    if (!log.beforeState) return false
    const created = new Date(log.createdAt).getTime()
    if (Number.isNaN(created)) return false
    const ageDays = (Date.now() - created) / (24 * 60 * 60 * 1000)
    return ageDays <= rollbackDays
  }

  const hasActiveFilters = !!(urlQ || operatorId || entityType || action || from || to || pageSize)

  if (isLoading && !data) return <PageLoading />

  const total = data?.total ?? 0
  const pages = data?.pages ?? 1
  const logs = data?.logs ?? []

  return (
    <>
      <h1 className="panel-title">审计日志</h1>
      <p className="panel-sub">
        共 {total} 条记录，第 {data?.page ?? page} / {pages} 页 · 仅可回滚 {rollbackDays} 天内的操作
      </p>

      {/* ── Filters ─────────────────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <form
          className="filters-grid"
          onSubmit={(e) => {
            e.preventDefault()
            setParam('q', search.trim())
          }}
        >
          <Input
            label="搜索"
            placeholder="操作者 / 实体名…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <Select label="操作类型" value={action} onChange={(e) => setParam('action', e.target.value)}>
            <option value="">全部</option>
            <option value="create">创建</option>
            <option value="update">更新</option>
            <option value="delete">删除</option>
          </Select>
          <Select
            label="实体类型"
            value={entityType}
            onChange={(e) => setParam('entity_type', e.target.value)}
          >
            <option value="">全部</option>
            <option value="user">用户</option>
            <option value="group">分组</option>
            <option value="role">角色</option>
            <option value="provider">登录方式</option>
            <option value="client">应用</option>
            <option value="project">项目</option>
            <option value="setting">设置</option>
            <option value="announcement">公告</option>
          </Select>
          <Input
            label="起始日期"
            type="date"
            value={from}
            onChange={(e) => setParam('from', e.target.value)}
          />
          <Input
            label="结束日期"
            type="date"
            value={to}
            onChange={(e) => setParam('to', e.target.value)}
          />
          <Select label="每页" value={pageSize} onChange={(e) => setParam('page_size', e.target.value)}>
            <option value="">默认 (50)</option>
            {(data?.pageSizeOpts ?? [20, 50, 100, 200]).map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </Select>
        </form>
        <div style={{ display: 'flex', gap: '.5rem', marginTop: '.75rem' }}>
          <Button size="sm" onClick={() => setParam('q', search.trim())}>
            搜索
          </Button>
          {hasActiveFilters && (
            <Link to="/admin/audit-logs" className="btn btn-ghost btn-sm">
              重置筛选
            </Link>
          )}
        </div>
      </div>

      {/* Top progress bar while fetching (not first load). */}
      {isFetching && <div className="is-fetching-bar" />}

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载审计日志失败，请稍后重试</EmptyState>
        ) : logs.length === 0 ? (
          <EmptyState>没有符合条件的记录</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作者</th>
                  <th>操作</th>
                  <th>实体</th>
                  <th>详情</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{new Date(log.createdAt).toLocaleString()}</td>
                    <td>
                      {log.operatorName || log.operatorId || '—'}
                      {log.operatorRole && (
                        <span style={{ color: 'var(--text2)', marginLeft: '.4rem', fontSize: '.8rem' }}>
                          {log.operatorRole}
                        </span>
                      )}
                    </td>
                    <td>{actionLabel(log.action)}</td>
                    <td>
                      {entityLabel(log.entityType)}
                      {log.entityName && (
                        <span style={{ color: 'var(--text2)', marginLeft: '.4rem' }}>
                          {log.entityName}
                        </span>
                      )}
                    </td>
                    <td>
                      <AuditDetails log={log} />
                    </td>
                    <td>
                      {canRollback(log) ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => askRollback(log)}
                          disabled={rollback.isPending}
                        >
                          回滚
                        </Button>
                      ) : (
                        <span style={{ color: 'var(--text2)' }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={data?.page ?? page} pages={pages} onPage={(p) => setParam('page', p)} />
      </div>
    </>
  )
}

// AuditDetails renders the before/after JSON states behind a <details> toggle.
function AuditDetails({ log }: { log: AuditLog }) {
  if (!log.beforeState && !log.afterState) return <span style={{ color: 'var(--text2)' }}>—</span>
  return (
    <details>
      <summary style={{ cursor: 'pointer', color: 'var(--text2)', fontSize: '.85rem' }}>查看</summary>
      <div style={{ marginTop: '.4rem', display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
        {log.beforeState && (
          <div>
            <div style={{ fontSize: '.75rem', color: 'var(--text2)' }}>变更前</div>
            <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {log.beforeState}
            </pre>
          </div>
        )}
        {log.afterState && (
          <div>
            <div style={{ fontSize: '.75rem', color: 'var(--text2)' }}>变更后</div>
            <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {log.afterState}
            </pre>
          </div>
        )}
      </div>
    </details>
  )
}

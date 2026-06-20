import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'
import type { User } from '@/api/types'

interface UserGroup {
  id: string
  name: string
  label: string
}

interface UserDetailResponse {
  user: User
  groups: UserGroup[]
}

const ROLE_LABELS: Record<string, string> = { admin: '管理员', member: '成员', user: '用户' }

function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? role
}

export default function UserDetail() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberUser(id),
    queryFn: () => api.get<UserDetailResponse>('/member/users/' + id),
    enabled: !!id,
  })

  const verifyMutation = useMutation({
    mutationFn: () => api.post('/member/users/' + id + '/verify-email'),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberUser(id) })
      qc.invalidateQueries({ queryKey: qk.memberUsers })
      toast(res.flash || '邮箱已验证', 'success')
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
    },
  })

  const toggleMutation = useMutation({
    mutationFn: () => api.post('/member/users/' + id + '/toggle-status'),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberUser(id) })
      qc.invalidateQueries({ queryKey: qk.memberUsers })
      toast(res.flash || '操作成功', 'success')
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
    },
  })

  async function onToggle(active: boolean) {
    if (active) {
      const ok = await confirm({
        title: '停用账户',
        message: '停用后该用户将无法登录，确认？',
        icon: '⚠️',
        danger: true,
      })
      if (!ok) return
    }
    toggleMutation.mutate()
  }

  if (isLoading) return <PageLoading />
  if (isError || !data) {
    return (
      <>
        <div style={{ marginBottom: '.5rem' }}>
          <Link to="/member/users" style={{ color: 'var(--text2)', fontSize: '.9rem' }}>
            ← 用户列表
          </Link>
        </div>
        <h1 className="panel-title">用户详情</h1>
        <div className="card">
          <EmptyState>加载用户失败或用户不存在</EmptyState>
        </div>
      </>
    )
  }

  const { user, groups } = data

  return (
    <>
      <div style={{ marginBottom: '.5rem' }}>
        <Link to="/member/users" style={{ color: 'var(--text2)', fontSize: '.9rem' }}>
          ← 用户列表
        </Link>
      </div>
      <h1 className="panel-title">{user.displayName || user.email}</h1>

      <div className="detail-section">
        <div className="detail-section-title">基本信息</div>
        <div className="detail-row">
          <div className="detail-key">邮箱</div>
          <div className="detail-val">{user.email}</div>
        </div>
        <div className="detail-row">
          <div className="detail-key">角色</div>
          <div className="detail-val">{roleLabel(user.role)}</div>
        </div>
        <div className="detail-row">
          <div className="detail-key">账户状态</div>
          <div className="detail-val">
            {user.active ? (
              <span style={{ color: '#166534', fontWeight: 500 }}>正常</span>
            ) : (
              <span style={{ color: '#991b1b', fontWeight: 500 }}>已停用</span>
            )}
          </div>
        </div>
        <div className="detail-row">
          <div className="detail-key">邮箱验证</div>
          <div className="detail-val">
            {user.emailVerified ? (
              <span style={{ color: '#166534' }}>已验证</span>
            ) : (
              <span style={{ color: '#991b1b' }}>未验证</span>
            )}
          </div>
        </div>
        <div className="detail-row">
          <div className="detail-key">注册时间</div>
          <div className="detail-val">{new Date(user.createdAt).toLocaleString()}</div>
        </div>
        <div className="detail-row">
          <div className="detail-key">所属分组</div>
          <div className="detail-val">
            {groups && groups.length > 0 ? (
              groups.map((g) => (
                <span key={g.id} className="proj-tag" style={{ marginRight: '.4rem' }}>
                  {g.label || g.name}
                </span>
              ))
            ) : (
              <span style={{ color: 'var(--text2)' }}>（无）</span>
            )}
          </div>
        </div>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">操作</div>
        <div style={{ display: 'flex', gap: '.8rem', flexWrap: 'wrap' }}>
          {!user.emailVerified && (
            <Button variant="ghost" size="sm" loading={verifyMutation.isPending} onClick={() => verifyMutation.mutate()}>
              验证邮箱
            </Button>
          )}
          {user.active ? (
            <Button variant="danger" size="sm" loading={toggleMutation.isPending} onClick={() => onToggle(true)}>
              停用账户
            </Button>
          ) : (
            <Button variant="ghost" size="sm" loading={toggleMutation.isPending} onClick={() => onToggle(false)}>
              启用账户
            </Button>
          )}
        </div>
      </div>
    </>
  )
}

import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { RoleBadge, EmptyState, PageLoading, StatusText } from '@/components/ui'
import type { User } from '@/api/types'

const ROLE_LABELS: Record<string, string> = { admin: '管理员', member: '成员', user: '用户' }

function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? role
}

export default function Users() {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberUsers,
    queryFn: () => api.get<User[]>('/member/users'),
  })

  if (isLoading) return <PageLoading />

  const users = data ?? []

  return (
    <>
      <h1 className="panel-title">用户列表</h1>
      <p className="panel-sub">查看所有用户信息，可验证邮箱和启停账户。</p>

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载用户列表失败，请稍后重试</EmptyState>
        ) : users.length === 0 ? (
          <EmptyState>暂无用户</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>邮箱</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>邮箱验证</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.displayName || '—'}</td>
                    <td style={{ fontSize: '.85rem' }}>{u.email}</td>
                    <td>
                      <RoleBadge role={u.role} label={roleLabel(u.role)} />
                    </td>
                    <td>
                      <StatusText active={u.active} on="正常" off="停用" />
                    </td>
                    <td>
                      <StatusText active={u.emailVerified} on="已验证" off="未验证" />
                    </td>
                    <td>
                      <Link to={`/member/users/${u.id}`} className="btn btn-ghost btn-sm">
                        详情
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

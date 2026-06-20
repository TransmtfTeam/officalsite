import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { EmptyState, PageLoading } from '@/components/ui'

// adminClientDTO from internal/server/api_admin_clients.go (camelCase JSON).
export interface AdminClient {
  id: string
  clientId: string
  name: string
  description: string
  redirectUris: string[]
  scopes: string[]
  baseAccess: string
  allowedGroups: string[]
  managerGroups: string[]
  createdAt: string
}

export default function Clients() {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.clients,
    queryFn: () => api.get<AdminClient[]>('/admin/clients'),
  })

  if (isLoading) return <PageLoading />

  const clients = data ?? []

  return (
    <>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          flexWrap: 'wrap',
          marginBottom: '.5rem',
        }}
      >
        <h1 className="panel-title" style={{ margin: 0 }}>
          应用管理
        </h1>
        <Link to="/admin/clients/new" className="btn btn-primary btn-sm">
          + 新建应用
        </Link>
      </div>
      <p className="panel-sub">管理授权登录应用。</p>

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载应用列表失败，请稍后重试</EmptyState>
        ) : clients.length === 0 ? (
          <EmptyState>暂无应用，点击右上角新建</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>应用标识</th>
                  <th>权限范围</th>
                  <th>回调地址列表</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link to={`/admin/clients/${c.id}`} style={{ fontWeight: 500 }}>
                        {c.name}
                      </Link>
                    </td>
                    <td>
                      <code className="mono" style={{ color: 'var(--blue-d)' }}>
                        {c.clientId}
                      </code>
                    </td>
                    <td style={{ fontSize: '.8rem' }}>
                      {c.scopes?.map((s) => (
                        <span key={s} className="proj-tag">
                          {s}
                        </span>
                      ))}
                    </td>
                    <td
                      style={{
                        fontSize: '.8rem',
                        maxWidth: 240,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {c.redirectUris?.map((u) => (
                        <div
                          key={u}
                          style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
                        >
                          {u}
                        </div>
                      ))}
                    </td>
                    <td>
                      <Link to={`/admin/clients/${c.id}`} className="btn btn-ghost btn-sm">
                        管理
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

import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card } from '@/components/ui'
import { Input, Textarea, FormGroup } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import type { AdminClient } from './Clients'

// Shape returned by POST /admin/clients: the created client plus the plaintext
// secret (shown ONCE).
interface CreateClientResponse {
  client: AdminClient
  clientSecret: string
}

export default function ClientCreate() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { toast } = useToast()

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [scopes, setScopes] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const mutation = useMutation({
    mutationFn: () =>
      // Input field names mirror adminClientCreateInput: name, description,
      // redirectUris (newline-separated), scopes (space-separated).
      api.post<CreateClientResponse>('/admin/clients', {
        name: name.trim(),
        description: description.trim(),
        redirectUris,
        scopes,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.clients })
      // Pass the created client + one-time secret to the confirmation page via
      // router state; that page shows the plaintext secret exactly once.
      navigate('/admin/clients/created', {
        state: { client: res.data.client, clientSecret: res.data.clientSecret },
      })
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        if (err.fieldErrors) setFieldErrors(err.fieldErrors)
        toast(err.message, 'error')
      } else {
        toast('创建失败', 'error')
      }
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!name.trim()) errs.name = '应用名称不能为空'
    if (redirectUris.split('\n').every((l) => l.trim() === '')) errs.redirectUris = '至少需要一个回调地址'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    mutation.mutate()
  }

  return (
    <>
      <p className="panel-sub" style={{ marginBottom: '.5rem' }}>
        <Link to="/admin/clients">← 返回列表</Link>
      </p>
      <h1 className="panel-title">新建应用</h1>
      <p className="panel-sub">注册一个新的授权登录应用。</p>

      <Card>
        <form onSubmit={submit}>
          <div className="form-row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <Input
              label={
                <>
                  应用名称 <span style={{ color: '#dc2626' }}>*</span>
                </>
              }
              value={name}
              onChange={(e) => setName(e.target.value)}
              error={fieldErrors.name}
              placeholder="新应用"
            />
            <Input
              label="描述（可选）"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="用于…的登录服务"
            />
          </div>

          <FormGroup
            label={
              <>
                回调地址列表（每行一个）<span style={{ color: '#dc2626' }}>*</span>
              </>
            }
            error={fieldErrors.redirectUris}
            hint="请填写安全协议地址，或本机调试地址。"
          >
            <Textarea
              rows={4}
              value={redirectUris}
              onChange={(e) => setRedirectUris(e.target.value)}
              placeholder="请逐行填写回调地址"
            />
          </FormGroup>

          <Input
            label="权限范围（空格分隔）"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            placeholder="留空使用默认权限项"
          />

          <div style={{ display: 'flex', gap: '.8rem', marginTop: '.5rem' }}>
            <Button type="submit" loading={mutation.isPending}>
              创建应用
            </Button>
            <Link to="/admin/clients" className="btn btn-ghost">
              取消
            </Link>
          </div>
        </form>
      </Card>
    </>
  )
}

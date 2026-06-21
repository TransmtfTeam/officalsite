import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { AuthCard } from '@/layouts/AuthLayout'
import { PageLoading } from '@/components/ui'

interface Challenge {
  challenge: string
  provider: string
  providerName: string
  profileName: string
  profileEmail: string
}

export default function OidcFirstLogin() {
  const [sp] = useSearchParams()
  const challenge = sp.get('challenge') ?? ''

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.oidcChallenge(challenge),
    queryFn: () => api.get<Challenge>('/login/oidc-challenge?challenge=' + encodeURIComponent(challenge)),
    enabled: !!challenge,
    retry: false,
  })

  if (!challenge || isError) {
    return (
      <AuthCard title="外部登录" footer={<Link to="/login">返回登录</Link>}>
        <div className="flash flash-err">外部登录流程已过期，请重新发起授权登录。</div>
      </AuthCard>
    )
  }
  if (isLoading || !data) return <PageLoading />

  return (
    <AuthCard title={`通过 ${data.providerName} 登录`}>
      <p style={{ color: 'var(--text2)', fontSize: '.92rem' }}>
        检测到外部账号 <span className="break">{data.profileEmail || data.profileName}</span>。请选择如何继续：
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '.6rem', marginTop: '1rem' }}>
        <Link className="btn btn-primary" to={`/login?oidc_challenge=${encodeURIComponent(challenge)}`} style={{ justifyContent: 'center' }}>
          绑定到已有账号
        </Link>
        <Link className="btn btn-ghost" to={`/register?oidc_challenge=${encodeURIComponent(challenge)}`} style={{ justifyContent: 'center' }}>
          注册新账号
        </Link>
      </div>
    </AuthCard>
  )
}

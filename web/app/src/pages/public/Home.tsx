import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { useAuth } from '@/providers/AuthProvider'

interface Project {
  id: string
  nameZH: string
  nameEN: string
  descZH: string
  descEN: string
  status: string
  url: string
  imageUrl: string
}
interface FriendLink {
  id: string
  name: string
  url: string
  icon: string
}
interface HomeData {
  projects: Project[]
  links: FriendLink[]
}

const INFO_CARDS = [
  { icon: '🌈', title: '什么是跨性别女性？', body: '跨性别女性即指出生时被指派男性性别，但内心认同自己是女性的跨性别者。这不是“选择”，而是性别认同的自然表达，被世界上主流医学组织广泛认可。' },
  { icon: '🏥', title: '医学与心理支持', body: '跨性别身份已被世界卫生组织、美国心理学会等机构去病理化。激素替代疗法、社会过渡等方式已被证明能显著改善跨性别者的心理健康与生活质量。' },
  { icon: '🤝', title: '社区与支持', body: '你不需要独自面对。这里有理解与接纳你的伙伴、资源与社区。无论你处于探索阶段还是已经走上了过渡之路，欢迎加入我们。' },
  { icon: '⚖️', title: '权利与尊重', body: '每一位跨性别女性都有权利被以正确的代词和名字称呼，被当作完整的人来尊重。跨性别女性是女性——这是不需要争论的事实。' },
  { icon: '💊', title: '激素替代疗法', body: '激素替代疗法通过引入雌激素、抗雄激素，使身体特征逐渐向女性方向发展，帮助缓解性别焦虑，提升生活幸福感。需要在医生指导下进行。' },
  { icon: '✨', title: '过渡的多种方式', body: '过渡可以是社会过渡（改名、着装、代词），医疗过渡（激素替代疗法、手术），或法律过渡（更改证件性别）。没有“唯一正确”的过渡方式，一切以你的意愿和安全为优先。' },
]

const MYTHS = [
  { color: '#55CDFC', title: '❌ 误区：跨性别是一种“选择”', body: '性别认同不是可以“选择”或“改变”的。跨性别身份是真实存在的，科学研究表明其有神经生物学基础。' },
  { color: '#F7A8B8', title: '❌ 误区：手术才是“真正的”跨性别', body: '是否进行手术是个人选择，与跨性别身份无关。一个没有做过任何手术的跨性别女性，依然是真实的女性。' },
  { color: '#C884B0', title: '❌ 误区：跨性别是心理疾病', body: '世界卫生组织已于 2019 年将跨性别去病理化。跨性别身份本身不是疾病，但被歧视带来的心理困扰需要社会支持。' },
]

const STATUS_LABEL: Record<string, string> = { active: '进行中', planning: '规划中', completed: '已完成' }

export default function Home() {
  const { user } = useAuth()
  const { data } = useQuery({ queryKey: qk.home, queryFn: () => api.get<HomeData>('/home') })
  const projects = data?.projects ?? []
  const links = data?.links ?? []

  return (
    <div style={{ background: '#fff' }}>
      <section className="page-hero" style={{ minHeight: '92vh' }}>
        <div className="hero-left">
          <p className="hero-greeting">了解我们</p>
          <p className="hero-prefix">什么是</p>
          <h1 className="hero-big">
            <span className="hc-1">跨</span>
            <span className="hc-2">性</span>
            <span className="hc-3">别</span>
            <span className="hc-4">女</span>
            <span className="hc-5">性</span>
          </h1>
          <p className="hero-also">跨女 · 跨性别女性</p>
          <p className="hero-trans">跨性别女性就是女性。</p>
          <p className="hero-desc" style={{ marginBottom: '2rem' }}>
            跨性别女性是出生时被指派为男性，但性别认同为女性的人。性别认同是每个人对自身性别的内心感受，与生理特征、社会性别表达无关。
          </p>
          <div style={{ display: 'flex', gap: '.8rem', flexWrap: 'wrap' }}>
            {user ? (
              <Link className="btn btn-primary" to="/profile">
                进入用户中心
              </Link>
            ) : (
              <>
                <Link className="btn btn-primary" to="/login">
                  登录账号
                </Link>
                <Link className="btn btn-ghost" to="/register">
                  创建账号
                </Link>
              </>
            )}
          </div>
        </div>
        <div className="hero-right">
          <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
            <div className="hero-blob" />
            <p className="hero-what-title">基本概念</p>
            <p className="hero-desc" style={{ marginBottom: '.9rem' }}>
              <span className="em-blue">性别认同</span>是一个人对自身性别的内在感受，与出生时被指派的性别（生理性别）可能一致，也可能不同。
            </p>
            <p className="hero-desc" style={{ marginBottom: '.9rem' }}>
              <span className="em-pink">跨性别</span>是一个总称，指性别认同与出生时被指派性别不符的人群。
            </p>
            <p className="hero-desc">
              <span className="em-purple">过渡</span>是跨性别者通过社会、医学或法律途径，使外界认知与自身性别认同一致的过程。
            </p>
          </div>
        </div>
      </section>

      <section className="mtf-section">
        <h2 className="section-title">关于跨性别女性</h2>
        <p className="section-sub">每个人的故事都不同，但你并不孤单。</p>
        <div className="cards-grid">
          {INFO_CARDS.map((c) => (
            <article className="info-card" key={c.title}>
              <div className="info-card-icon">{c.icon}</div>
              <div className="info-card-title">{c.title}</div>
              <div className="info-card-body">{c.body}</div>
            </article>
          ))}
        </div>
      </section>

      <section className="mtf-section-white">
        <h2 className="section-title">常见误区</h2>
        <p className="section-sub">关于跨性别，有很多误解需要澄清。</p>
        <div className="cards-grid">
          {MYTHS.map((m) => (
            <article className="info-card" key={m.title} style={{ borderLeft: `4px solid ${m.color}` }}>
              <div className="info-card-title">{m.title}</div>
              <div className="info-card-body">{m.body}</div>
            </article>
          ))}
        </div>
      </section>

      <section className="section">
        <h2 className="section-title">社区项目</h2>
        <p className="section-sub">我们正在建设的一些项目与资源。</p>
        <div className="cards-grid">
          {projects.length === 0 ? (
            <article className="proj-card">
              <p className="proj-desc">暂无公开项目，敬请期待。</p>
            </article>
          ) : (
            projects.map((p) => {
              const name = p.nameZH || p.nameEN
              const desc = p.descZH || p.descEN
              return (
                <article className="proj-card" key={p.id}>
                  <div className="proj-card-header">
                    <span className="proj-name">{name}</span>
                    <span className={`proj-status proj-status-${p.status}`}>{STATUS_LABEL[p.status] ?? p.status}</span>
                  </div>
                  {desc && <p className="proj-desc">{desc}</p>}
                  {p.url && (
                    <a className="proj-link" href={p.url} target="_blank" rel="noopener noreferrer">
                      访问项目 →
                    </a>
                  )}
                  {p.imageUrl && (
                    <img
                      src={p.imageUrl}
                      alt={name}
                      style={{ marginTop: '.8rem', width: '100%', borderRadius: 6, objectFit: 'cover', maxHeight: 180 }}
                    />
                  )}
                </article>
              )
            })
          )}
        </div>
      </section>

      {links.length > 0 && (
        <section className="mtf-section-white" style={{ paddingTop: '2.5rem', paddingBottom: '3rem' }}>
          <h2 className="section-title" style={{ fontSize: '1.3rem' }}>
            友情链接
          </h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '.8rem 1.2rem', justifyContent: 'center', marginTop: '1rem' }}>
            {links.map((l) => (
              <a
                key={l.id}
                href={l.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '.45rem',
                  padding: '.45rem .9rem',
                  borderRadius: 8,
                  background: 'rgba(255,255,255,0.7)',
                  border: '1px solid rgba(0,0,0,0.08)',
                  color: 'var(--text)',
                  textDecoration: 'none',
                  fontSize: '.9rem',
                }}
              >
                {l.icon && <img src={l.icon} alt="" style={{ width: 16, height: 16, objectFit: 'contain', flexShrink: 0 }} />}
                {l.name}
              </a>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}

import { Button } from './ui'

interface Props {
  page: number
  pages: number
  onPage: (p: number) => void
}

export function Pagination({ page, pages, onPage }: Props) {
  if (pages <= 1) return null
  return (
    <div
      className="pager"
      style={{ display: 'flex', gap: '.4rem', alignItems: 'center', justifyContent: 'flex-end', padding: '1rem', flexWrap: 'wrap' }}
    >
      <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPage(1)}>
        首页
      </Button>
      <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        上一页
      </Button>
      <span style={{ fontSize: '.88rem', color: 'var(--text2)', margin: '0 .4rem' }}>
        第 {page} / {pages} 页
      </span>
      <Button variant="ghost" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        下一页
      </Button>
      <Button variant="ghost" size="sm" disabled={page >= pages} onClick={() => onPage(pages)}>
        末页
      </Button>
    </div>
  )
}

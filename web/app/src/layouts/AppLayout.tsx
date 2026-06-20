import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { TopNav } from './TopNav'
import { Sidebar } from './Sidebar'
import { AnnouncementModal } from '@/components/AnnouncementModal'

// AppLayout is the authenticated shell: top nav + sidebar (drawer on mobile) +
// panel content. Sidebar open state drives the mobile drawer + backdrop.
export function AppLayout() {
  const [open, setOpen] = useState(false)

  return (
    <>
      <TopNav onToggleSidebar={() => setOpen((v) => !v)} />
      <div className={`sidebar-backdrop${open ? ' active' : ''}`} onClick={() => setOpen(false)} />
      <div className="panel-wrap">
        <Sidebar open={open} onNavigate={() => setOpen(false)} />
        <main className="panel-content">
          <Outlet />
        </main>
      </div>
      <AnnouncementModal />
    </>
  )
}

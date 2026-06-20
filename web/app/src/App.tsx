import { Routes, Route } from 'react-router-dom'
import { PublicLayout } from './layouts/PublicLayout'
import { AuthLayout } from './layouts/AuthLayout'
import { AppLayout } from './layouts/AppLayout'
import { RequireAuth } from './routes/guards/RequireAuth'
import { RequirePermission } from './routes/guards/RequirePermission'
import { RedirectIfAuthed } from './routes/guards/RedirectIfAuthed'

import Home from './pages/public/Home'
import Tos from './pages/public/Tos'
import Privacy from './pages/public/Privacy'
import NotFound from './pages/public/NotFound'

import Login from './pages/auth/Login'
import Register from './pages/auth/Register'
import ForgotPassword from './pages/auth/ForgotPassword'
import ResetPassword from './pages/auth/ResetPassword'
import VerifyEmail from './pages/auth/VerifyEmail'
import Login2FA from './pages/auth/Login2FA'
import OidcFirstLogin from './pages/auth/OidcFirstLogin'
import ForceChangePassword from './pages/auth/ForceChangePassword'

import Consent from './pages/oauth/Consent'
import Profile from './pages/profile/Profile'

import Dashboard from './pages/admin/Dashboard'
import Users from './pages/admin/Users'
import UserDetail from './pages/admin/UserDetail'
import Clients from './pages/admin/Clients'
import ClientCreate from './pages/admin/ClientCreate'
import ClientCreated from './pages/admin/ClientCreated'
import ClientDetail from './pages/admin/ClientDetail'
import Providers from './pages/admin/Providers'
import ProviderEdit from './pages/admin/ProviderEdit'
import Roles from './pages/admin/Roles'
import Announcements from './pages/admin/Announcements'
import Settings from './pages/admin/Settings'
import Groups from './pages/admin/Groups'
import GroupDetail from './pages/admin/GroupDetail'
import AuditLogs from './pages/admin/AuditLogs'

import MemberProjects from './pages/member/Projects'
import ProjectEdit from './pages/member/ProjectEdit'
import MemberLinks from './pages/member/Links'
import LinkEdit from './pages/member/LinkEdit'
import MemberUsers from './pages/member/Users'
import MemberUserDetail from './pages/member/UserDetail'

export function App() {
  return (
    <Routes>
      <Route element={<PublicLayout />}>
        <Route path="/" element={<Home />} />
        <Route path="/tos" element={<Tos />} />
        <Route path="/privacy" element={<Privacy />} />
      </Route>

      <Route element={<AuthLayout />}>
        <Route element={<RedirectIfAuthed />}>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
        </Route>
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/login/2fa" element={<Login2FA />} />
        <Route path="/auth/oidc/first-login" element={<OidcFirstLogin />} />
      </Route>

      <Route element={<RequireAuth />}>
        <Route element={<AuthLayout />}>
          <Route path="/oauth2/authorize" element={<Consent />} />
          <Route path="/profile/change-password" element={<ForceChangePassword />} />
        </Route>

        <Route element={<AppLayout />}>
          <Route path="/profile" element={<Profile />} />

          <Route element={<RequirePermission admin />}>
            <Route path="/admin" element={<Dashboard />} />
            <Route path="/admin/audit-logs" element={<AuditLogs />} />
          </Route>
          <Route element={<RequirePermission perm="manage_users" />}>
            <Route path="/admin/users" element={<Users />} />
            <Route path="/admin/users/:id" element={<UserDetail />} />
          </Route>
          <Route element={<RequirePermission perm="manage_clients" />}>
            <Route path="/admin/clients" element={<Clients />} />
            <Route path="/admin/clients/new" element={<ClientCreate />} />
            <Route path="/admin/clients/created" element={<ClientCreated />} />
            <Route path="/admin/clients/:id" element={<ClientDetail />} />
          </Route>
          <Route element={<RequirePermission perm="manage_providers" />}>
            <Route path="/admin/providers" element={<Providers />} />
            <Route path="/admin/providers/:id/edit" element={<ProviderEdit />} />
          </Route>
          <Route element={<RequirePermission perm="manage_roles" />}>
            <Route path="/admin/roles" element={<Roles />} />
          </Route>
          <Route element={<RequirePermission perm="manage_announcements" />}>
            <Route path="/admin/announcements" element={<Announcements />} />
          </Route>
          <Route element={<RequirePermission perm="manage_settings" />}>
            <Route path="/admin/settings" element={<Settings />} />
          </Route>
          <Route element={<RequirePermission perm="manage_groups" />}>
            <Route path="/admin/groups" element={<Groups />} />
            <Route path="/admin/groups/:id" element={<GroupDetail />} />
          </Route>

          <Route element={<RequirePermission perm="manage_projects" />}>
            <Route path="/member/projects" element={<MemberProjects />} />
            <Route path="/member/projects/:id/edit" element={<ProjectEdit />} />
            <Route path="/member/links" element={<MemberLinks />} />
            <Route path="/member/links/:id/edit" element={<LinkEdit />} />
          </Route>
          <Route element={<RequirePermission perm="view_users" />}>
            <Route path="/member/users" element={<MemberUsers />} />
            <Route path="/member/users/:id" element={<MemberUserDetail />} />
          </Route>
        </Route>
      </Route>

      <Route element={<PublicLayout />}>
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}

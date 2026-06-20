export interface User {
  id: string
  email: string
  displayName: string
  avatarUrl: string
  role: string
  active: boolean
  emailVerified: boolean
  totpEnabled: boolean
  requirePasswordChange: boolean
  createdAt: string
}

export interface Capabilities {
  isAdmin: boolean
  isMember: boolean
  isSystemAdmin: boolean
  permissions: string[]
}

export interface SiteSettings {
  siteName: string
  siteIconUrl: string
  issuer: string
  contactEmail: string
  annZH: string
  annEN: string
  annHash: string
}

export interface Me {
  user: User | null
  csrfToken: string
  requirePasswordChange: boolean
  settings: SiteSettings
  capabilities: Capabilities
}

export type Permission =
  | 'manage_users'
  | 'manage_clients'
  | 'manage_projects'
  | 'view_users'
  | 'moderate_users'
  | 'manage_providers'
  | 'manage_roles'
  | 'manage_announcements'
  | 'manage_settings'
  | 'manage_groups'

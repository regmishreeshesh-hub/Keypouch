export type Role = 'view' | 'modify' | 'full-access' | 'admin';
export type Resource = 'secrets' | 'contacts';
export type Action = 'create' | 'read' | 'update' | 'delete' | 'share';
export interface PermissionContext {
  isOwner?: boolean;
}

export const getRole = (): Role => {
  const role = localStorage.getItem('role');
  if (role === 'admin' || role === 'full-access' || role === 'modify' || role === 'view') {
    return role;
  }
  return 'view';
};

export const canReadSecrets = (role: Role) => role === 'view' || role === 'modify' || role === 'full-access' || role === 'admin';
export const canCreateSecrets = (role: Role) => role === 'modify' || role === 'full-access' || role === 'admin';
export const canUpdateSecrets = (role: Role) => role === 'modify' || role === 'full-access' || role === 'admin';
export const canDeleteSecrets = (role: Role, options?: { isOwner?: boolean }) => {
  if (role === 'full-access' || role === 'admin') return true;
  if (role === 'modify') return Boolean(options?.isOwner);
  return false;
};
export const canShareSecrets = (role: Role) => role === 'full-access' || role === 'admin';

export const canReadContacts = (role: Role) => role === 'view' || role === 'modify' || role === 'full-access' || role === 'admin';
export const canCreateContacts = (role: Role) => role === 'modify' || role === 'full-access' || role === 'admin';
export const canUpdateContacts = (role: Role) => role === 'modify' || role === 'full-access' || role === 'admin';
export const canDeleteContacts = (role: Role) => role === 'full-access' || role === 'admin';

export const can = (role: Role, resource: Resource, action: Action, context?: PermissionContext) => {
  if (resource === 'secrets') {
    if (action === 'read') return canReadSecrets(role);
    if (action === 'create') return canCreateSecrets(role);
    if (action === 'update') return canUpdateSecrets(role);
    if (action === 'delete') return canDeleteSecrets(role, { isOwner: context?.isOwner });
    if (action === 'share') return canShareSecrets(role);
  }

  if (resource === 'contacts') {
    if (action === 'read') return canReadContacts(role);
    if (action === 'create') return canCreateContacts(role);
    if (action === 'update') return canUpdateContacts(role);
    if (action === 'delete') return canDeleteContacts(role);
    if (action === 'share') return false;
  }

  return false;
};

// Backwards-compatible helpers used across the UI.
export const canModify = (role: Role) => canCreateSecrets(role) || canCreateContacts(role);
export const canDelete = (role: Role) => canDeleteContacts(role);
export const canShare = (role: Role) => canShareSecrets(role);
export const canManageCategories = (role: Role) => canUpdateSecrets(role);

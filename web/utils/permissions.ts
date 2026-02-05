export type Role = 'view' | 'modify' | 'full-access' | 'admin';

export const getRole = (): Role => {
  const role = localStorage.getItem('role');
  if (role === 'admin' || role === 'full-access' || role === 'modify' || role === 'view') {
    return role;
  }
  return 'view';
};

export const canModify = (role: Role) => role === 'modify' || role === 'full-access' || role === 'admin';
export const canDelete = (role: Role) => role === 'full-access' || role === 'admin';

// Sharing and custom-category changes are "create/edit" actions.
export const canShare = (role: Role) => canModify(role);
export const canManageCategories = (role: Role) => canModify(role);

/** Root of the versioned backend API. Relative so the SPA works behind any host. */
export const API_ROOT = '/api/v1';

/** Build an organization-scoped API path. */
export function orgPath(organizationId: string, suffix = ''): string {
  return `${API_ROOT}/organizations/${organizationId}${suffix}`;
}

/** Read a browser cookie value, or null when it is absent. */
export function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return null;
}

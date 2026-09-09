/**
 * Keyboard focus for dialogs and drawers.
 *
 * A container that declares itself modal has to behave as one: focus moves
 * into it when it opens, Tab stays inside it, and focus returns to whatever
 * opened it when it closes. Nothing here depends on a framework.
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * The elements inside `host` a user can Tab to, in document order.
 *
 * Hidden state is read from the markup rather than from layout: a layout
 * query answers nothing where there is no layout, and the containers this
 * serves hide content by attribute.
 */
export function focusables(host: HTMLElement): HTMLElement[] {
  return Array.from(host.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) => element.closest('[hidden], [aria-hidden="true"]') === null,
  );
}

/** Keep a Tab press inside `host`, wrapping at either end. */
export function trapTab(event: KeyboardEvent, host: HTMLElement): void {
  if (event.key !== 'Tab') {
    return;
  }
  const candidates = focusables(host);
  if (candidates.length === 0) {
    event.preventDefault();
    host.focus();
    return;
  }
  const first = candidates[0];
  const last = candidates[candidates.length - 1];
  const active = document.activeElement;
  if (event.shiftKey && (active === first || active === host)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

/** Remember what has focus now, so it can be given back later. */
export function rememberFocus(): HTMLElement | null {
  return document.activeElement instanceof HTMLElement ? document.activeElement : null;
}

/** Give focus back to an element remembered earlier, if it is still on the page. */
export function restoreFocus(target: HTMLElement | null): void {
  if (target?.isConnected) {
    target.focus();
  }
}

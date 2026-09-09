/**
 * Timestamp formatting for the application.
 *
 * The design renders times in the terse monospace form the prototype uses
 * (`07 SEP 14:22Z`). Audit correlation depends on everyone reading the same
 * clock, so UTC is the default; the account preference can widen it.
 */

export interface ClockPreference {
  timezone: string;
  clock: '24h' | '12h';
}

const UTC: ClockPreference = { timezone: 'UTC', clock: '24h' };

// Intl's short month is locale- and ICU-version dependent ("Sept" in newer
// en-GB data). The design uses fixed three-letter months, so we map explicitly.
const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

function monthIndex(value: Date, timezone: string): number {
  const numeric = new Intl.DateTimeFormat('en-GB', { timeZone: timezone, month: 'numeric' }).format(value);
  return Number(numeric) - 1;
}

function shortMonth(value: Date, timezone: string, titleCase = false): string {
  const month = MONTHS[monthIndex(value, timezone)];
  return titleCase ? month.charAt(0) + month.slice(1).toLowerCase() : month;
}

function parts(value: Date, preference: ClockPreference): Record<string, string> {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: preference.timezone,
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: preference.clock === '12h',
  });
  const result: Record<string, string> = {};
  for (const part of formatter.formatToParts(value)) {
    result[part.type] = part.value;
  }
  return result;
}

/** `07 SEP 14:22Z` — the shell's as-of and timeline label form. */
export function formatInstant(value: Date, preference: ClockPreference = UTC): string {
  const p = parts(value, preference);
  const suffix = preference.timezone === 'UTC' ? 'Z' : '';
  const meridiem = p['dayPeriod'] ? ` ${p['dayPeriod'].toUpperCase()}` : '';
  return `${p['day']} ${shortMonth(value, preference.timezone)} ${p['hour']}:${p['minute']}${suffix}${meridiem}`;
}

/** `09:12Z` — the compact time used in feed and table rows. */
export function formatTime(value: Date, preference: ClockPreference = UTC): string {
  const p = parts(value, preference);
  const suffix = preference.timezone === 'UTC' ? 'Z' : '';
  const meridiem = p['dayPeriod'] ? ` ${p['dayPeriod'].toUpperCase()}` : '';
  return `${p['hour']}:${p['minute']}${suffix}${meridiem}`;
}

/** `MON 07 SEP` — the day separator in the changes table. */
export function formatDay(value: Date, preference: ClockPreference = UTC): string {
  const weekday = new Intl.DateTimeFormat('en-GB', {
    timeZone: preference.timezone,
    weekday: 'short',
  })
    .format(value)
    .toUpperCase();
  const p = parts(value, preference);
  return `${weekday} ${p['day']} ${shortMonth(value, preference.timezone)}`;
}

/** `07 Sep 2026` — long-form dates in settings and account. */
export function formatDate(value: Date, preference: ClockPreference = UTC): string {
  const p = parts(value, preference);
  return `${p['day']} ${shortMonth(value, preference.timezone, true)} ${p['year']}`;
}

/** `5h 10m` — the distance between two instants, at minute resolution. */
export function formatDuration(fromValue: Date, toValue: Date = new Date()): string {
  const totalMinutes = Math.max(0, Math.round((toValue.getTime() - fromValue.getTime()) / 60_000));
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

/** `1,284` — thousands separators for object counts. */
export function formatCount(value: number): string {
  return new Intl.NumberFormat('en-GB').format(value);
}

/** `26M AGO` — coarse relative age used in approval and session rows. */
export function formatAgo(value: Date, now: Date = new Date()): string {
  const minutes = Math.max(0, Math.round((now.getTime() - value.getTime()) / 60_000));
  if (minutes < 60) {
    return `${minutes}M AGO`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 48) {
    return `${hours}H AGO`;
  }
  return `${Math.round(hours / 24)}D AGO`;
}

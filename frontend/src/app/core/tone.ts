import { ImpactSeverity } from './change-group.model';

/** The five semantic tones the design uses for badges, rules, and metrics. */
export type Tone = 'crit' | 'warn' | 'ok' | 'none' | 'info';

/** Map a backend impact severity onto the design's tone vocabulary. */
export function toneOf(severity: ImpactSeverity): Tone {
  switch (severity) {
    case 'critical':
      return 'crit';
    case 'warning':
      return 'warn';
    case 'info':
      return 'info';
    default:
      return 'none';
  }
}

/** Ink colour token for a tone, for inline styling of values and markers. */
export function toneInk(tone: Tone): string {
  return `var(--tone-${TOKEN[tone]}-ink)`;
}

const TOKEN: Record<Tone, string> = {
  crit: 'critical',
  warn: 'warning',
  ok: 'ok',
  none: 'none',
  info: 'info',
};

import { ChangeDetectionStrategy, Component, ElementRef, effect, inject, signal, untracked, viewChild } from '@angular/core';

import { StepUpService } from '../core/step-up.service';

/**
 * The authenticator code a sensitive action asks for when the last one has
 * aged out. Mounted in the shell because the request it unblocks can come from
 * any page, and the interceptor that raises it has no view of its own.
 */
@Component({
  selector: 'app-step-up-prompt',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (stepUp.asking()) {
      <div class="scrim" (click)="dismiss()"></div>
      <section
        class="cg-card prompt"
        role="dialog"
        aria-modal="true"
        aria-labelledby="step-up-title"
        (keydown)="onKey($event)"
      >
        <h2 class="prompt-title" id="step-up-title">Confirm it is still you</h2>
        <p class="prompt-sub">
          This change needs a recent authenticator code. Enter the current one, or a recovery code
          if you cannot reach your authenticator.
        </p>
        <div class="field">
          <label class="cg-label" for="step-up-code">Authenticator code</label>
          <input
            #codeInput
            id="step-up-code"
            class="cg-input code-input"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            [value]="code()"
            (input)="setCode($event)"
          />
        </div>
        @if (stepUp.error(); as message) {
          <p class="prompt-error" role="alert">{{ message }}</p>
        }
        <div class="row">
          <button
            class="cg-btn cg-btn--primary cg-btn--lg"
            type="button"
            [disabled]="!code() || stepUp.busy()"
            (click)="submit()"
          >
            {{ stepUp.busy() ? 'Confirming…' : 'Confirm' }}
          </button>
          <button class="cg-btn cg-btn--lg" type="button" (click)="dismiss()">Cancel</button>
        </div>
      </section>
    }
  `,
  styles: `
    .scrim {
      position: fixed;
      inset: 0;
      z-index: 70;
      background: rgba(20, 22, 26, 0.14);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
    }

    .prompt {
      position: fixed;
      top: 50%;
      left: 50%;
      z-index: 71;
      width: min(420px, calc(100vw - 32px));
      padding: 18px;
      transform: translate(-50%, -50%);
      display: grid;
      gap: 12px;
    }

    .prompt-title {
      margin: 0;
      font-size: 13px;
      font-weight: 600;
    }

    .prompt-sub {
      margin: 0;
      color: var(--ink-muted);
    }

    .prompt-error {
      margin: 0;
      color: var(--tone-critical-ink);
    }

    .field {
      display: grid;
      gap: 6px;
    }

    .code-input {
      font-family: var(--font-mono);
      letter-spacing: 0.18em;
    }

    .row {
      display: flex;
      gap: 8px;
    }
  `,
})
export class StepUpPrompt {
  protected readonly stepUp = inject(StepUpService);
  protected readonly code = signal('');

  private readonly codeInput = viewChild<ElementRef<HTMLInputElement>>('codeInput');

  constructor() {
    effect(() => {
      const input = this.codeInput()?.nativeElement;
      if (input) {
        untracked(() => input.focus());
      } else {
        untracked(() => this.code.set(''));
      }
    });
  }

  protected setCode(event: Event): void {
    this.code.set((event.target as HTMLInputElement).value.trim());
  }

  protected async submit(): Promise<void> {
    const code = this.code();
    if (!code) {
      return;
    }
    await this.stepUp.submit(code);
    // Whether it was accepted or not, the code is used up: a time-based one is
    // good for one window, and a recovery code for one use.
    this.code.set('');
  }

  protected dismiss(): void {
    this.code.set('');
    this.stepUp.dismiss();
  }

  protected onKey(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.dismiss();
    }
  }
}

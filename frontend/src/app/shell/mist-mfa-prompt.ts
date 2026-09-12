import { ChangeDetectionStrategy, Component, effect, ElementRef, inject, viewChild } from '@angular/core';
import { MistMfaService } from '../core/mist-mfa.service';

@Component({
  selector: 'app-mist-mfa-prompt',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <dialog #dialog aria-labelledby="mist-mfa-title" (cancel)="cancel()">
      <form (submit)="$event.preventDefault(); verify(code.value)">
        <h2 id="mist-mfa-title">Verify your Mist account</h2>
        <p>{{ mfa.prompt()?.message }}</p>
        <label class="cg-label" for="mist-mfa-code">MIST VERIFICATION CODE</label>
        <input #code id="mist-mfa-code" name="two_factor" class="cg-input"
          type="text" autocomplete="one-time-code" required autofocus />
        <div class="actions">
          <button class="cg-btn cg-btn--primary" type="submit">Verify</button>
          <button class="cg-btn" type="button" (click)="cancel()">Cancel</button>
        </div>
      </form>
    </dialog>
  `,
  styles: `
    dialog { width: min(420px, calc(100vw - 48px)); padding: 24px; border: 1px solid var(--border);
      border-radius: 12px; background: var(--surface-raised); color: var(--ink); }
    dialog::backdrop { background: rgb(0 0 0 / 50%); }
    h2 { margin-top: 0; } p { line-height: 1.5; } input { width: 100%; margin-top: 8px; }
    .actions { display: flex; gap: 12px; margin-top: 24px; }
  `,
})
export class MistMfaPrompt {
  protected readonly mfa = inject(MistMfaService);
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  constructor() {
    effect(() => {
      const prompt = this.mfa.prompt();
      const dialog = this.dialog().nativeElement;
      if (prompt) {
        dialog.querySelector('form')?.reset();
        if (!dialog.open) dialog.showModal();
      } else if (dialog.open) {
        dialog.close();
        dialog.querySelector('form')?.reset();
      }
    });
  }

  protected verify(code: string): void {
    if (code.trim()) this.mfa.prompt()?.complete(code.trim());
  }

  protected cancel(): void {
    this.mfa.prompt()?.complete(null);
  }
}

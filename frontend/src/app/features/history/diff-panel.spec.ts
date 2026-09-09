import { TestBed } from '@angular/core/testing';
import { DiffPanel } from './diff-panel';
import { alignRawLines } from './raw-diff';

describe('DiffPanel raw comparison', () => {
  it('highlights changes with text markers, preserves gaps and renders JSON as text', () => {
    const fixture = TestBed.createComponent(DiffPanel);
    fixture.componentRef.setInput('compact', false);
    fixture.componentRef.setInput('sectioned', false);
    fixture.componentRef.setInput('rawExpanded', true);
    fixture.componentRef.setInput('rawRows', alignRawLines(['same', '<img src=x onerror=alert(1)>', 'gone'], ['same', 'new']));
    fixture.detectChanges();
    const element: HTMLElement = fixture.nativeElement;
    expect(element.querySelectorAll('.raw-line--removed').length).toBe(2);
    expect(element.querySelectorAll('.raw-line--added').length).toBe(1);
    expect(element.querySelectorAll('.raw-line--empty').length).toBe(1);
    expect(element.querySelector('img')).toBeNull();
    expect(element.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(element.textContent).toContain('Removed:');
    expect(element.textContent).toContain('Added:');
    fixture.componentRef.setInput('rawExpanded', false);
    fixture.detectChanges();
    expect(element.querySelector('.raw-grid')).toBeNull();
  });
});

import { SiteContextService } from './site-context.service';

describe('shared site selection', () => {
  it('remembers each organization independently and clears on session reset', () => {
    const sites = new SiteContextService();
    sites.select('org1', 'paris');
    sites.select('org2', 'london');
    expect(sites.selectedFor('org1')).toBe('paris');
    expect(sites.selectedFor('org2')).toBe('london');
    expect(sites.selectedFor('org3')).toBe('');
    sites.select('org1', '');
    expect(sites.selectedFor('org1')).toBe('');
    expect(sites.selectedFor('org2')).toBe('london');
    sites.reset();
    expect(sites.selectedFor('org2')).toBe('');
  });
});

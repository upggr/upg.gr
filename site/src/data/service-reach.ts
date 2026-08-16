/**
 * How many client businesses are on each service.
 *
 * Base figures come from the active subscription export
 * (subscriptions-export-2026-08-16.json: 65 clients, 322 active
 * subscriptions), plus two public-sector clients billed outside it:
 *
 *   Γενικό Νοσοκομείο Ζακύνθου — 250 Microsoft 365 seats, 250 protected devices
 *   Επιμελητήριο Ζακύνθου      —  10 Microsoft 365 seats,   5 protected devices
 *
 * Aggregate counts only — no client names, VAT numbers, billing addresses or
 * prices are stored here or published. Refresh by re-running the aggregation
 * against a newer export and updating `asOf`.
 */
export const serviceReachAsOf = '2026-08-16';

/** Headline totals, used for the hero stats. */
export const totals = {
  clients: 67,
  microsoft365Seats: 462,
  protectedDevices: 433,
} as const;

export const serviceReach = [
  { id: 'microsoft365', count: 36 },
  { id: 'hosting', count: 27 },
  { id: 'domains', count: 21 },
  { id: 'security', count: 22 },
  { id: 'cloud', count: 7 },
  { id: 'booking', count: 3 },
] as const;

export type ServiceReachId = (typeof serviceReach)[number]['id'];

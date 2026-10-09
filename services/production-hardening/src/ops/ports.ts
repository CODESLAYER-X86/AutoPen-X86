/**
 * Ports consumed by the hardening service (kept interface-only so the
 * service stays independent of transport concerns).
 */
import type { PlatformEvent } from '@aegis/contracts';

export interface EventPort {
  publish(event: PlatformEvent): Promise<void>;
}

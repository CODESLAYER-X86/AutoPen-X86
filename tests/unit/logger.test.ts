import { describe, expect, it } from 'vitest';
import { createLogger, createMemorySink } from '@aegis/logging';

describe('structured logger', () => {
  it('emits single-line JSON with ts/level/event and bindings', () => {
    const { sink, lines } = createMemorySink();
    const logger = createLogger({ level: 'info', sink, bindings: { service: 'test' } });
    logger.info('tool.execution.completed', { engagement_id: 'ENG_X', duration_ms: 214 });
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(parsed.level).toBe('info');
    expect(parsed.event).toBe('tool.execution.completed');
    expect(parsed.service).toBe('test');
    expect(parsed.engagement_id).toBe('ENG_X');
    expect(parsed.duration_ms).toBe(214);
    expect(typeof parsed.ts).toBe('string');
  });

  it('respects level filtering', () => {
    const { sink, lines } = createMemorySink();
    const logger = createLogger({ level: 'warn', sink });
    logger.info('ignored');
    logger.warn('kept');
    logger.error('kept too');
    expect(lines).toHaveLength(2);
  });

  it('child loggers inherit bindings and add their own', () => {
    const { sink, lines } = createMemorySink();
    const logger = createLogger({ level: 'info', sink, bindings: { service: 'api' } });
    logger.child({ engagement_id: 'ENG_1' }).info('event.with.scope');
    const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(parsed.service).toBe('api');
    expect(parsed.engagement_id).toBe('ENG_1');
  });

  it('redacts secrets passing through metadata', () => {
    const { sink, lines } = createMemorySink();
    const logger = createLogger({ level: 'info', sink });
    logger.info('auth.attempt', { password: 'supersecret', email: 'a@b.c' });
    const line = lines[0]!;
    expect(line).not.toContain('supersecret');
    expect(line).toContain('[REDACTED]');
  });

  it('never throws when the sink fails', () => {
    const logger = createLogger({
      level: 'info',
      sink: {
        write: () => {
          throw new Error('sink exploded');
        },
      },
    });
    expect(() => logger.info('event')).not.toThrow();
  });
});

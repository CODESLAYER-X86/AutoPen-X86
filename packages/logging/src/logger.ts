/**
 * Structured JSON logger (spec §23).
 *
 * Every line is a single JSON object with `ts`, `level`, `event` plus bound
 * correlation metadata (`engagement_id`, `task_id`, `trace_id`, ...).
 * All metadata passes through the redaction engine before serialisation.
 */
import { redactRecord } from './redact.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LogSink {
  write(line: string): void;
}

export const consoleSink: LogSink = {
  write(line: string): void {
    process.stdout.write(`${line}\n`);
  },
};

/** In-memory sink used by tests to assert that secrets never reach logs. */
export function createMemorySink(): { sink: LogSink; lines: string[] } {
  const lines: string[] = [];
  return { sink: { write: (line) => lines.push(line) }, lines };
}

export interface Logger {
  readonly level: LogLevel;
  child(bindings: Record<string, unknown>): Logger;
  debug(event: string, meta?: Record<string, unknown>): void;
  info(event: string, meta?: Record<string, unknown>): void;
  warn(event: string, meta?: Record<string, unknown>): void;
  error(event: string, meta?: Record<string, unknown>): void;
  log(level: LogLevel, event: string, meta?: Record<string, unknown>): void;
}

export interface JsonLoggerOptions {
  level?: LogLevel;
  bindings?: Record<string, unknown>;
  sink?: LogSink;
  redact?: boolean;
}

export class JsonLogger implements Logger {
  readonly level: LogLevel;
  private readonly bindings: Record<string, unknown>;
  private readonly sink: LogSink;
  private readonly redact: boolean;

  constructor(options: JsonLoggerOptions = {}) {
    this.level = options.level ?? 'info';
    this.bindings = options.bindings ?? {};
    this.sink = options.sink ?? consoleSink;
    this.redact = options.redact ?? true;
  }

  child(bindings: Record<string, unknown>): Logger {
    return new JsonLogger({
      level: this.level,
      bindings: { ...this.bindings, ...bindings },
      sink: this.sink,
      redact: this.redact,
    });
  }

  debug(event: string, meta?: Record<string, unknown>): void {
    this.log('debug', event, meta);
  }

  info(event: string, meta?: Record<string, unknown>): void {
    this.log('info', event, meta);
  }

  warn(event: string, meta?: Record<string, unknown>): void {
    this.log('warn', event, meta);
  }

  error(event: string, meta?: Record<string, unknown>): void {
    this.log('error', event, meta);
  }

  log(level: LogLevel, event: string, meta?: Record<string, unknown>): void {
    if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[this.level]) return;
    const safeMeta = meta === undefined ? {} : this.redact ? redactRecord(meta) : meta;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      event,
      ...this.bindings,
      ...safeMeta,
    });
    try {
      this.sink.write(line);
    } catch {
      // A logging failure must never crash the application.
    }
  }
}

export function createLogger(options: JsonLoggerOptions = {}): Logger {
  return new JsonLogger(options);
}

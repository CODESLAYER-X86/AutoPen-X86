import { describe, expect, it } from 'vitest';
import { ConfigurationError } from '@aegis/shared';
import { loadConfig, parseEnvFile, validateEnv } from '@aegis/config';

describe('configuration validation (spec §33)', () => {
  it('applies defaults for a minimal environment', () => {
    const config = loadConfig({ env: {} });
    expect(config.app.port).toBe(4000);
    expect(config.app.logLevel).toBe('info');
    expect(config.models.strategic.provider).toBe('mock');
    expect(config.features.toolsHttp).toBe(true); // Part 3: interaction tools implemented
    expect(config.security.corsOrigins).toEqual(['http://localhost:5173']);
  });

  it('rejects an invalid DATABASE_URL with a typed error', () => {
    expect(() => loadConfig({ env: { DATABASE_URL: 'file:./whatever.db' } })).toThrowError(
      ConfigurationError,
    );
    try {
      loadConfig({ env: { DATABASE_URL: 'not-a-url' } });
    } catch (error) {
      const configurationError = error as ConfigurationError;
      expect(configurationError.code).toBe('CONFIG_VALIDATION_FAILED');
      const details = configurationError.details as { variable: string }[];
      expect(details.some((d) => d.variable === 'DATABASE_URL')).toBe(true);
    }
  });

  it('rejects invalid enum values', () => {
    expect(() => loadConfig({ env: { STRATEGIC_MODEL_PROVIDER: 'openai-unknown' } })).toThrowError(
      ConfigurationError,
    );
    expect(() => loadConfig({ env: { APP_LOG_LEVEL: 'verbose' } })).toThrowError(ConfigurationError);
  });

  it('rejects out-of-range numbers', () => {
    expect(() => loadConfig({ env: { APP_PORT: '99999' } })).toThrowError(ConfigurationError);
    expect(() => loadConfig({ env: { DATABASE_POOL_MAX: '0' } })).toThrowError(ConfigurationError);
  });

  it('coerces numeric and boolean strings', () => {
    const config = loadConfig({ env: { APP_PORT: '8080', BROWSER_ENABLED: 'true' } });
    expect(config.app.port).toBe(8080);
    expect(config.browser.enabled).toBe(true);
  });

  it('coerces Part 8 hardening numeric strings (fresh .env.example copy)', () => {
    // Regression: these three knobs shipped with z.number() instead of
    // z.coerce.number(), so a fresh `cp .env.example .env` (all values are
    // strings there) failed CONFIG_VALIDATION_FAILED on a clean clone.
    const config = loadConfig({
      env: {
        HARDENING_API_KEY_TTL_HOURS: '720',
        HARDENING_GRANT_TTL_MINUTES: '60',
        HARDENING_BREAKER_DEFAULT_THRESHOLD: '5',
      },
    });
    expect(config.hardening.apiKeyTtlHours).toBe(720);
    expect(config.hardening.grantTtlMinutes).toBe(60);
    expect(config.hardening.breakerDefaultThreshold).toBe(5);
  });

  it('ignores empty-string variables (treats them as unset)', () => {
    const config = loadConfig({ env: { SECRET_STORE_MASTER_KEY: '' } });
    expect(config.secretStore.masterKey).toBeUndefined();
  });

  it('does NOT copy raw secret values into the config object', () => {
    const config = loadConfig({ env: { GOOGLE_API_KEY: 'AIzaSyVerySecretKey123456789012345' } });
    const serialised = JSON.stringify(config);
    expect(serialised).not.toContain('AIzaSyVerySecretKey123456789012345');
    expect(config.models.googleApiKeyConfigured).toBe(true);
  });

  it('parses .env files with comments and quoting', () => {
    const parsed = parseEnvFile(
      ['# comment\n', 'APP_NAME="Aegis Dev"', 'APP_PORT=4100', '  SPACED = value  ', 'BADLINE\n'].join('\n'),
    );
    expect(parsed.APP_NAME).toBe('Aegis Dev');
    expect(parsed.APP_PORT).toBe('4100');
    expect(parsed.SPACED).toBe('value');
    expect(parsed.BADLINE).toBeUndefined();
  });

  it('refuses to load a .env file in production', () => {
    expect(() =>
      loadConfig({ env: { NODE_ENV: 'production' }, envFile: '/tmp/whatever.env' }),
    ).toThrowError(ConfigurationError);
  });

  it('validateEnv exposes the parsed env for tests', () => {
    const env = validateEnv({ APP_PORT: '9000' });
    expect(env.APP_PORT).toBe(9000);
  });
});

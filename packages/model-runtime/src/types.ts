/**
 * Model runtime abstraction (spec §18).
 *
 * The orchestrator NEVER talks to a vendor SDK directly; it talks to the
 * `ModelProvider` interface. Providers are selected by configuration
 * (STRATEGIC_MODEL_PROVIDER / TACTICAL_MODEL_PROVIDER) so the model behind
 * a role can be changed without code changes.
 */
import type { ModelRole } from '@aegis/shared';

export type { ModelRole };

export interface ModelMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface GenerateRequest {
  messages: ModelMessage[];
  system?: string;
  /**
   * JSON Schema describing the REQUIRED shape of the model's content.
   * Providers that support structured output pass it to the backend;
   * the caller must STILL validate the returned content (never trust
   * model output blindly — spec §1.3).
   */
  responseJsonSchema?: Record<string, unknown>;
  maxOutputTokens?: number;
  temperature?: number;
}

export interface TokenUsage {
  inputTokens?: number;
  outputTokens?: number;
}

export interface GenerateResult {
  content: string;
  provider: string;
  model: string;
  usage?: TokenUsage;
  finishReason?: string;
}

export interface ModelCapabilities {
  streaming: boolean;
  jsonSchema: boolean;
  tools: boolean;
}

export interface ModelProvider {
  readonly id: string;
  readonly model: string;
  capabilities(): ModelCapabilities;
  generate(request: GenerateRequest): Promise<GenerateResult>;
  /** Optional capability — providers without it report streaming: false. */
  stream?(request: GenerateRequest): AsyncIterable<string>;
  /** Optional capability. */
  countTokens?(text: string): Promise<number>;
}

export interface ModelRouterOptions {
  strategic: ModelProvider;
  tactical: ModelProvider;
}

/** Resolves providers per logical role (spec §19). */
export class ModelRouter {
  private readonly providers: Map<ModelRole, ModelProvider>;

  constructor(options: ModelRouterOptions) {
    this.providers = new Map<ModelRole, ModelProvider>([
      ['strategic', options.strategic],
      ['tactical', options.tactical],
    ]);
  }

  forRole(role: ModelRole): ModelProvider {
    const provider = this.providers.get(role);
    if (!provider) throw new Error(`No provider registered for role '${role}'`);
    return provider;
  }

  all(): ModelProvider[] {
    return [...this.providers.values()];
  }
}

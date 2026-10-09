-- Part 5 — Structured security techniques (spec §42-§43, §46) and
-- extracted references (§57, §76) with hypothesis cross-links (§59).
-- Techniques describe WHY/WHEN to test and what signal matters — the
-- knowledge base is not a payload dump (§44).
CREATE TABLE security_techniques (
    id text PRIMARY KEY,
    name text NOT NULL,
    category text NOT NULL,
    description text NOT NULL,
    preconditions jsonb NOT NULL DEFAULT '[]'::jsonb,
    signals jsonb NOT NULL DEFAULT '[]'::jsonb,
    test_patterns jsonb NOT NULL DEFAULT '[]'::jsonb,
    verification_patterns jsonb NOT NULL DEFAULT '[]'::jsonb,
    false_positive_conditions jsonb NOT NULL DEFAULT '[]'::jsonb,
    source_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    confidence numeric NOT NULL DEFAULT 0.5,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_techniques_name_unique UNIQUE (name),
    CONSTRAINT security_techniques_category_check CHECK (category IN ('AUTHENTICATION','AUTHORIZATION','SESSION','INPUT_VALIDATION','INJECTION','XSS','CSRF','SSRF','FILE_HANDLING','API','GRAPHQL','WEBSOCKET','BUSINESS_LOGIC','RACE_CONDITION','CRYPTO','CONFIGURATION','INFORMATION_DISCLOSURE','CLIENT_SIDE')),
    CONSTRAINT security_techniques_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX idx_security_techniques_category ON security_techniques (category);

-- CVE/CWE/OWASP/RFC references (§57, §76). A CVE is a knowledge reference,
-- NOT evidence of target vulnerability (§76).
CREATE TABLE knowledge_references (
    id text PRIMARY KEY,
    document_id text REFERENCES knowledge_documents (id) ON DELETE CASCADE,
    chunk_id text REFERENCES knowledge_chunks (id) ON DELETE CASCADE,
    technique_id text REFERENCES security_techniques (id) ON DELETE CASCADE,
    hypothesis_id text,
    kind text NOT NULL,
    value text NOT NULL,
    context text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_references_kind_check CHECK (kind IN ('CVE','CWE','OWASP','RFC','OTHER'))
);

CREATE INDEX idx_knowledge_references_value ON knowledge_references (kind, value);
CREATE INDEX idx_knowledge_references_hypothesis ON knowledge_references (hypothesis_id);
CREATE INDEX idx_knowledge_references_document ON knowledge_references (document_id);

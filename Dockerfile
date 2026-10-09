# syntax=docker/dockerfile:1
# Part 8 §71: container hardening — multi-stage build, non-root runtime user,
# minimal base, dropped capabilities, no host docker socket ever mounted.

# --- build stage -------------------------------------------------------------
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.base.json vitest.shared.ts ./
COPY packages packages
COPY services services
COPY apps apps
RUN npm run build:server && npm run build -w apps/web

# --- runtime stage ------------------------------------------------------------
FROM node:24-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Non-root dedicated user (§71).
RUN groupadd -r aegis && useradd -r -g aegis -d /app -s /usr/sbin/nologin aegis
COPY --from=build --chown=aegis:aegis /app/package.json /app/package-lock.json ./
COPY --from=build --chown=aegis:aegis /app/node_modules ./node_modules
COPY --from=build --chown=aegis:aegis /app/packages ./packages
COPY --from=build --chown=aegis:aegis /app/services ./services
COPY --from=build --chown=aegis:aegis /app/apps ./apps
COPY --from=build --chown=aegis:aegis /app/tsconfig.json /app/tsconfig.base.json ./
# Only the API server runs in the container; the web bundle is served
# separately (see docs/operations/deployment.md).
RUN mkdir -p /app/data && chown -R aegis:aegis /app/data
USER aegis
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "apps/api/dist/server.js"]

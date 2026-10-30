FROM node:24.22.0-alpine3.24 AS toolchain
RUN npm install --global npm@11.18.0

FROM toolchain AS dependencies
WORKDIR /app
COPY .npmrc package.json package-lock.json ./
RUN npm ci

FROM toolchain AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
# Defaults so `next build` can reach the cookies() call that marks every
# protected route dynamic instead of throwing before it gets there, in a dev
# build that never overrides these. NEBULA_ADMIN_ORIGIN also feeds
# next.config.ts's serverActions.allowedOrigins, which next.config.ts only
# ever reads at build time -- unlike NEBULA_API_INTERNAL_URL, which is read
# per-request at container runtime, a real deployment MUST override this
# build arg with its actual public origin or every Server Action (e.g. the
# admin dashboard's Requests page) fails behind a reverse proxy on a
# non-default port.
ARG NEBULA_API_INTERNAL_URL=http://api:8000
ARG NEBULA_ADMIN_ORIGIN=http://localhost:3000
ENV NEBULA_API_INTERNAL_URL=${NEBULA_API_INTERNAL_URL}
ENV NEBULA_ADMIN_ORIGIN=${NEBULA_ADMIN_ORIGIN}
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24.22.0-alpine3.24 AS runner
WORKDIR /app
ENV HOSTNAME=0.0.0.0
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000

# The pinned base image predates later Alpine security patches; take them
# here rather than waiting for Docker Hub to republish this exact tag.
RUN apk upgrade --no-cache

RUN rm -rf /usr/local/lib/node_modules/npm \
  && rm -f /usr/local/bin/npm /usr/local/bin/npx

RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]

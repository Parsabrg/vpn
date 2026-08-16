FROM node:26.7.0-alpine3.23 AS toolchain
RUN npm install --global npm@11.18.0

FROM toolchain AS dependencies
WORKDIR /app
COPY .npmrc package.json package-lock.json ./
RUN npm ci

FROM toolchain AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
# Placeholder values so `next build` can reach the cookies() call that marks
# every protected route dynamic instead of throwing before it gets there; the
# real values are supplied at container runtime (see compose.yaml).
ENV NEBULA_API_INTERNAL_URL=http://api:8000
ENV NEBULA_ADMIN_ORIGIN=http://localhost:3000
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:26.7.0-alpine3.23 AS runner
WORKDIR /app
ENV HOSTNAME=0.0.0.0
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000

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

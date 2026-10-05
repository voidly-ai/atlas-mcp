FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
ENV NODE_ENV=production
# Inspection default: agent_register must fail before its external POST.
# A real owner may override this only with a private persistent credential store.
ENV VOIDLY_MCP_RELAY_HOME=/etc/voidly-mcp-relay
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
COPY LICENSE ./LICENSE
USER node
CMD ["node", "dist/index.js"]

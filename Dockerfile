FROM node:20-bookworm-slim AS deps
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev


FROM node:20-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000

# Kopiera node_modules från deps-stage
COPY --from=deps /app/node_modules ./node_modules

# Kopiera applikationen
COPY . .

# Skapa uploads-katalogen med rättigheter
RUN mkdir -p /app/uploads/chat \
    && chown -R 1000:1000 /app/uploads

# Kör som non-root
USER 1000:1000

EXPOSE 8000
CMD ["node", "server.js"]

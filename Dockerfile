FROM node:20-alpine
WORKDIR /app

# Install deps with or without a lockfile
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev; \
    fi

# Copy source
COPY . .

ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "server.js"]

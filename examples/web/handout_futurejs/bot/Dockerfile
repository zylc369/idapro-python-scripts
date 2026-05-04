FROM node:20-bookworm-slim

WORKDIR /bot

RUN apt-get update \
  && apt-get install -y --no-install-recommends chromium ca-certificates fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_DOWNLOAD=true

COPY package*.json ./
RUN npm install --omit=dev

COPY server.js ./server.js
COPY public ./public

EXPOSE 3000
CMD ["npm", "run", "start"]

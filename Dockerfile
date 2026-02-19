FROM node:20-bookworm-slim

# Install Chromium and dependencies required by whatsapp-web.js/puppeteer
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libgtk-3-0 \
    libx11-xcb1 \
    libxcb1 \
    libx11-6 \
    libxcursor1 \
    libxext6 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first (better cache)
COPY package*.json ./
RUN npm install --omit=dev

# Copy source
COPY . .

ENV NODE_ENV=production
ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV WHATSAPP_CHROME_PATH=/usr/bin/chromium

EXPOSE 3000

CMD ["npm","start"]

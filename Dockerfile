FROM node:20-alpine

# build tools required to compile better-sqlite3's native module
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV PORT=3000
ENV ADMIN_PORT=3001
ENV DATA_DIR=/app/data

EXPOSE 3000
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:'+(process.env.PORT||3000)+'/api/health', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]

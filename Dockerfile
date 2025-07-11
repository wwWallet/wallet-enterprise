FROM node:22-bullseye-slim AS builder

WORKDIR /app
COPY . .

RUN apt-get update -y && apt-get install -y git && rm -rf /var/lib/apt/lists/* && git clone --branch master --single-branch --depth 1 https://github.com/wwWallet/wallet-common.git ./lib/wallet-common

WORKDIR /app/lib/wallet-common
RUN git checkout 22897828ec42f951410c6250cb0d1ea246ca4db1
RUN yarn install && yarn build


WORKDIR /app


RUN yarn cache clean && yarn install && yarn build && rm -rf node_modules/ && yarn install --production

# Production stage
FROM node:22-bullseye-slim AS production
WORKDIR /app

COPY --from=builder /app/lib/wallet-common/ ./lib/wallet-common/
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json .
COPY --from=builder /app/dist/ ./dist/
COPY --from=builder /app/public/ ./public/
COPY --from=builder /app/views/ ./views/


ENV NODE_ENV=production
EXPOSE 8003

CMD ["node", "./dist/src/app.js"]
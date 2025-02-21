FROM node:22-bullseye-slim

WORKDIR /app
COPY . .

COPY lib/ ./lib
WORKDIR /app/lib/core
RUN yarn install && yarn cache clean -f && yarn build && rm -rf node_modules && yarn install --production

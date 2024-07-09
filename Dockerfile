# Builder stage
FROM node:20-bullseye-slim AS builder
WORKDIR /home/node/app

COPY . .
RUN --mount=type=secret,id=npmrc,required=true,target=./.npmrc,uid=1000 \
    yarn cache clean && yarn install && yarn build

# Production stage
FROM node:20-bullseye-slim AS production
WORKDIR /home/node/app

COPY --from=builder /home/node/app/package.json .
COPY --from=builder /home/node/app/dist ./dist
COPY --from=builder /home/node/app/public ./public
COPY --from=builder /home/node/app/views ./views


RUN --mount=type=secret,id=npmrc,required=true,target=./.npmrc,uid=1000 \
    yarn cache clean && yarn install --production

ENV NODE_ENV production
EXPOSE 8003

CMD ["node", "./dist/src/app.js"]
FROM node:22-bullseye-slim AS wallet-common-builder

WORKDIR /lib/wallet-common
COPY ./lib/wallet-common/package.json ./lib/wallet-common/yarn.lock ./
RUN yarn install --pure-lockfile

COPY ./lib/wallet-common/ ./
RUN yarn build


FROM node:22-bullseye-slim AS builder-base

WORKDIR /app

COPY package.json yarn.lock .
COPY --from=wallet-common-builder /lib/wallet-common/ ./lib/wallet-common/
RUN yarn install --pure-lockfile


FROM builder-base AS development

ENV NODE_ENV=development
EXPOSE 8003
CMD ["yarn", "dev-docker"]

# Sources will be mounted from host, but we need some config files in the image for startup
COPY . .

# Set user last so everything is readonly by default
USER node

# Don't need the rest of the sources since they'll be mounted from host


FROM builder-base AS builder

COPY . .
RUN yarn build && yarn install --production


FROM node:22-bullseye-slim AS production

WORKDIR /app
COPY --from=builder /app/node_modules/ ./node_modules/
COPY --from=builder /app/package.json .
COPY --from=builder /app/dist/ ./dist/
COPY --from=builder /app/public/ ./public/
COPY --from=builder /app/views/ ./views/

ENV NODE_ENV=production
EXPOSE 8003

CMD ["node", "./dist/src/app.js"]

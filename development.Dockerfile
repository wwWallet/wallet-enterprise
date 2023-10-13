FROM node:16-bullseye-slim
WORKDIR /home/node/app

# Copy package.json and yarn.lock and npmrc to the container
COPY package.json yarn.lock .npmrc ./


RUN mkdir -p /home/node/app/node_modules
COPY --chown=node:node . .
RUN yarn install

# Copy the rest of the application code to the container

ENV NODE_ENV development

RUN mkdir -p dist


RUN chown -R node:node  /home/node/app/node_modules
RUN chown -R node:node  /home/node/app/dist

EXPOSE 8003
USER node
CMD ["yarn", "dev"]
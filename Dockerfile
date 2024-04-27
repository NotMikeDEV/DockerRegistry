FROM node:20
WORKDIR /opt
RUN mkdir -p /var/lib/registry
COPY package.json .
RUN npm install
COPY tsconfig.json .
COPY tsup.config.ts .
COPY src src
RUN npm run build
CMD ["npm", "start"]
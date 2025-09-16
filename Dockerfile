FROM node:22-alpine
ENV APP_DIR=/fuzzer-engine
ENV FUZZER_ENGINE_PORT=8080
ENV NODE_OPTIONS="--disable-warning=DEP0174"

WORKDIR ${APP_DIR}
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE ${FUZZER_ENGINE_PORT}
CMD ["npm", "start"]
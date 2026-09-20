FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY dist ./dist
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV PORT=4173
EXPOSE 4173
CMD ["node", "server/app.js"]

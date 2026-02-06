FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
# use --legacy-peer-deps to avoid strict peer resolution failures in CI/docker
RUN npm install --legacy-peer-deps --verbose

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]

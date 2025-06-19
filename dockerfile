FROM node:20-bookworm

WORKDIR /app

# Установка build-зависимостей
RUN apt-get update && \
    apt-get install -y python3 make g++ build-essential && \
    rm -rf /var/lib/apt/lists/*

# Установка зависимостей
COPY package*.json ./
RUN npm ci --no-optional

COPY . .

CMD ["npm", "start"]
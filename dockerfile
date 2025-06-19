# Берём официальный образ Node.js 20 (LTS)
FROM node:20-bookworm

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем package.json и устанавливаем зависимости
COPY package*.json ./
RUN npm install --no-optional

# Копируем остальные файлы
COPY . .

# Открываем порт
EXPOSE 3000

# Запускаем приложение
CMD ["npm", "start"]
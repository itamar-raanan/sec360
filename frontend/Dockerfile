FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage with nginx
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.d/40-reload-certificates.sh /docker-entrypoint.d/40-reload-certificates.sh
RUN chmod +x /docker-entrypoint.d/40-reload-certificates.sh

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]

# CyberGuard AI - Frontend Dockerfile
# Multi-stage build for React + Vite application

# ============================================
# Stage 1: Build
# ============================================
FROM node:20-alpine as builder

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source code
COPY . .

# Vite bakes VITE_* vars into the static bundle at BUILD time, not runtime -
# a plain Nginx container serving the already-built dist/ can never pick
# these up from `environment:` in docker-compose.yml. They must come in as
# build args instead (see docker-compose.yml's frontend `build.args:`).
ARG VITE_API_URL=/api/v1
ARG VITE_FIREBASE_PROJECT_ID=
ARG VITE_FIREBASE_API_KEY=
ARG VITE_FIREBASE_AUTH_DOMAIN=
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_FIREBASE_PROJECT_ID=$VITE_FIREBASE_PROJECT_ID
ENV VITE_FIREBASE_API_KEY=$VITE_FIREBASE_API_KEY
ENV VITE_FIREBASE_AUTH_DOMAIN=$VITE_FIREBASE_AUTH_DOMAIN

# Build for production
RUN npm run build

# ============================================
# Stage 2: Production (Nginx)
# ============================================
FROM nginx:alpine as production

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

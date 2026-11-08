# ============================================================================
# CyberGuard AI — Frontend Dockerfile
# ============================================================================
# 
# Multi-stage build:
#   Stage 1 (builder): Uses Node.js to compile the React/Vite app.
#   Stage 2 (nginx):   Uses Nginx to serve the static files.
#
# This means the final container does NOT contain Node.js, NPM, or the 
# node_modules folder — only the compiled HTML/JS/CSS and Nginx.
# ============================================================================

# ── Stage 1: Build ───────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
# We copy package.json and package-lock.json first to leverage Docker caching.
# If the source code changes but dependencies don't, Docker skips this layer.
COPY package.json package-lock.json* ./
RUN npm ci

# Copy the rest of the source code
COPY . .

# Build the production bundle
# This outputs optimized static files to /app/dist
RUN npm run build


# ── Stage 2: Serve ───────────────────────────────────────────────────────
FROM nginx:alpine

# Remove the default Nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy the compiled assets from the builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy our custom Nginx configuration (we will build this in File 210)
# It handles React Router (SPA fallback) and proxies /api to the backend.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose HTTP port
EXPOSE 80

# Start Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]
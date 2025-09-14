# syntax = docker/dockerfile:1 

# Adjust NODE_VERSION as desired
ARG NODE_VERSION=20.18.0
FROM node:${NODE_VERSION}-slim AS base

LABEL fly_launch_runtime="Node.js"

WORKDIR /app
ENV NODE_ENV="production"

# Throw-away build stage
FROM base AS build

# Install build deps
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential node-gyp pkg-config python-is-python3 && \
    rm -rf /var/lib/apt/lists/*

# 🚀 Install legacy tools needed by some packages
RUN npm install -g grunt-cli bower

# Install node modules
COPY package-lock.json package.json ./
RUN npm ci --ignore-scripts --legacy-peer-deps


# Copy application code
COPY . .

# Final stage
FROM base

COPY --from=build /app /app

EXPOSE 3000
CMD ["npm", "run", "start"]

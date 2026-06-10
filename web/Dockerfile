# Dockerfile
FROM node:18-slim

# Create and set the working directory
WORKDIR /usr/src/app

# Install build dependencies for sqlite3 (requires compilation)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install dependencies (only production to minimize image size)
RUN npm ci --only=production

# Copy application source code
COPY . .

# Expose the default port (Cloud Run sets PORT env var automatically)
EXPOSE 3000

# Start the server
CMD [ "node", "server.js" ]

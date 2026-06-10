# Use official Node.js runtime as parent image
FROM node:18-alpine

# Set working directory inside the container
WORKDIR /app

# Copy package files
COPY web/package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy the rest of the web application
COPY web/ .

# Expose port
EXPOSE 3000

# Set production environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Run the app
CMD ["node", "server.js"]

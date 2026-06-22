FROM php:8.2-cli-alpine

# Install required extensions
RUN docker-php-ext-install opcache

# Add OpenSSL (already in base image)
RUN apk add --no-cache openssl

# Set working directory
WORKDIR /app

# Copy files
COPY . /app/

# Create data directories
RUN mkdir -p /app/var/keys /app/var/sessions /app/var/tickets /app/var/logs && \
    chmod 700 /app/var

EXPOSE 8080

# Start built-in PHP server
CMD ["php", "-S", "0.0.0.0:8080", "router.php"]

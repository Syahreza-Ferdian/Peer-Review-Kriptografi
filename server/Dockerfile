FROM php:8.2-cli

RUN apt-get update && \
    apt-get install -y \
        python3 \
        libzip-dev \
        default-mysql-client && \
    docker-php-ext-install mysqli && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

EXPOSE 8000

CMD ["php", "-S", "0.0.0.0:8000"]
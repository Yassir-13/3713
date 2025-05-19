FROM php:8.2-fpm

# Installer dépendances système
RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg-dev libfreetype6-dev \
    libcurl4-openssl-dev libssl-dev \
    libxml2-dev libxslt1-dev libyaml-dev \
    zlib1g-dev build-essential \
    git curl unzip jq gnupg bash ruby ruby-dev \
    libicu-dev python3 python3-pip nmap

# Config GD + extensions PHP
RUN docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install gd pdo pdo_mysql xml xsl intl

# Nettoyage
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Installer Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Installer Ruby et Bundler (si pas déjà fait)
RUN gem install bundler -v 2.4.22

# Cloner et installer WhatWeb manuellement
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && cd /opt/whatweb \
    && bundle install

# Ajouter WhatWeb au PATH pour pouvoir l'utiliser partout
ENV PATH="/opt/whatweb:$PATH"

# Installer SSLyze
# Installer venv et créer un environnement virtuel
RUN apt-get update && apt-get install -y python3-venv

# Créer un venv et installer sslyze dedans
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install sslyze

# Ajouter le venv au PATH
ENV PATH="/opt/venv/bin:$PATH"

# Installer ZAP Python API (pas zap-cli, mais tu peux faire des requêtes HTTP via API key)
RUN pip3 install python-owasp-zap-v2.4

# Définir le répertoire de travail
WORKDIR /var/www/html

# Copier composer.json pour les dépendances Laravel
COPY composer.json composer.lock ./

# Installer dépendances Laravel
RUN composer install --no-interaction --prefer-dist --optimize-autoloader

# Copier le reste du code
COPY . .

EXPOSE 8000

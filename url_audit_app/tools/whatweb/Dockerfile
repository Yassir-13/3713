FROM ruby:2.7-slim

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    git build-essential ca-certificates && \
    git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb

# Installer la version compatible de Bundler
RUN gem install bundler -v 2.4.22

# Installer les dépendances Ruby du projet
WORKDIR /opt/whatweb
RUN bundle install

# Ajouter WhatWeb au PATH
ENV PATH="/opt/whatweb:$PATH"

CMD ["tail", "-f", "/dev/null"]

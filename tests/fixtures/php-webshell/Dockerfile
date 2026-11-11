FROM php:8.3-apache

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# The fixture must not advertise itself or leak key material through errors.
RUN { \
      echo 'expose_php=Off'; \
      echo 'display_errors=Off'; \
      echo 'log_errors=On'; \
      echo 'error_reporting=E_ALL & ~E_DEPRECATED'; \
      echo 'max_execution_time=20'; \
      echo 'memory_limit=128M'; \
      echo 'post_max_size=32K'; \
      echo 'upload_max_filesize=1K'; \
      echo 'allow_url_fopen=Off'; \
    } > /usr/local/etc/php/conf.d/artex-fixture.ini

COPY index.php healthz.php /var/www/html/
RUN chown -R www-data:www-data /var/www/html && chmod 0644 /var/www/html/*.php

HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1/healthz.php || exit 1

EXPOSE 80

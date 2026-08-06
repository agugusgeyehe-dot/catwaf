# PHP-FPM backend for the split-architecture fixture.
#
# Built as `fake-web-php` — an image name that does NOT contain "php-fpm",
# so correlation has to rely on the running process and the nginx config
# rather than a convenient image tag. That is the realistic case.

FROM php:8.3-fpm-alpine

WORKDIR /var/www/html
COPY www/ /var/www/html/

EXPOSE 9000
CMD ["php-fpm", "-F"]

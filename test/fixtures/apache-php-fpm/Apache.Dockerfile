# Apache front end for the split PHP-FPM fixture.
#
# The official httpd image ships mod_proxy and mod_proxy_fcgi but leaves
# them disabled, so they are enabled here — that is what makes the
# `ProxyPassMatch ... fcgi://` line in vhost.conf actually work, and it is
# the wiring discovery/fastcgi.js correlates on.

FROM httpd:2.4-alpine

RUN sed -i \
    -e 's|^#\(LoadModule proxy_module\)|\1|' \
    -e 's|^#\(LoadModule proxy_fcgi_module\)|\1|' \
    /usr/local/apache2/conf/httpd.conf

COPY vhost.conf /usr/local/apache2/conf/extra/booknook.conf
RUN echo 'Include conf/extra/booknook.conf' >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80

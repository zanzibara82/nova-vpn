FROM alpine:3.20
# Интерфейс клиента настраивается явными командами ip/wg: wg-quick вызывает
# sysctl, а /proc/sys в контейнере только для чтения. Правила nftables при этом
# не нужны. bind-tools даёт nslookup для проверки резолвера, tcpdump — снимок
# eth0 для проверки утечки DNS.
RUN apk add --no-cache bash wireguard-tools iproute2 curl iputils bind-tools tcpdump \
    && mkdir -p /state \
    && chmod 0700 /state
COPY infrastructure/docker/e2e/client-entrypoint.sh /usr/local/bin/client-entrypoint.sh
RUN chmod 0755 /usr/local/bin/client-entrypoint.sh
VOLUME ["/state"]
ENTRYPOINT ["/usr/local/bin/client-entrypoint.sh"]
CMD ["run"]
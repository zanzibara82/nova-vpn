FROM alpine:3.20
# nftables нужен самому wg-quick: для AllowedIPs=0.0.0.0/0 он строит policy
# routing и ставит правила nft; без nft/iptables подъём интерфейса обрывается.
RUN apk add --no-cache bash wireguard-tools iproute2 curl iputils nftables \
    && mkdir -p /state \
    && chmod 0700 /state
COPY infrastructure/docker/e2e/client-entrypoint.sh /usr/local/bin/client-entrypoint.sh
RUN chmod 0755 /usr/local/bin/client-entrypoint.sh
VOLUME ["/state"]
ENTRYPOINT ["/usr/local/bin/client-entrypoint.sh"]
CMD ["run"]
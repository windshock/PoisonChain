FROM jenkins/inbound-agent:latest
USER root
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends curl jq nodejs npm iptables iproute2 2>/dev/null && \
    rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER jenkins
ENTRYPOINT ["/entrypoint.sh"]

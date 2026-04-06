FROM jenkins/jenkins:2.492.2-lts-jdk17

USER root

# Install Docker CE CLI (official repo) for GuardDog wrapper - Debian docker.io is too old
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# GuardDog wrapper: delegates to the official Docker image via the host Docker socket
RUN printf '#!/bin/sh\ndocker run --rm -v "$(pwd):/workspace" -w /workspace ghcr.io/datadog/guarddog "$@"\n' \
    > /usr/local/bin/guarddog && chmod +x /usr/local/bin/guarddog

USER jenkins

# Install plugins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Pre-load job configs (copied to $JENKINS_HOME on first start)
COPY jobs/ /usr/share/jenkins/ref/jobs/

ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc.yaml

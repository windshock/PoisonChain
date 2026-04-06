#!/bin/bash
set -e
MASTER_URL="${MASTER_URL:-http://jenkins:8080}"
AGENT_NAME="${AGENT_NAME:-docker-agent}"

echo "[agent] Jenkins master 대기 중: $MASTER_URL"
until curl -sf "$MASTER_URL/api/json" -u admin:admin123 > /dev/null 2>&1; do
    sleep 3
done
echo "[agent] Master 연결 확인"

# JNLP에서 secret 자동 추출
SECRET=$(curl -sf "$MASTER_URL/computer/$AGENT_NAME/slave-agent.jnlp" \
    -u admin:admin123 \
    | grep -oP '(?<=<argument>)[0-9a-f]{64}(?=</argument>)' \
    | head -1)

if [ -z "$SECRET" ]; then
    echo "[agent] ❌ secret 획득 실패 — master가 아직 node를 생성하지 않았을 수 있음. 재시도..."
    sleep 10
    SECRET=$(curl -sf "$MASTER_URL/computer/$AGENT_NAME/slave-agent.jnlp" \
        -u admin:admin123 \
        | grep -oP '(?<=<argument>)[0-9a-f]{64}(?=</argument>)' \
        | head -1)
fi

echo "[agent] secret 획득 완료 (앞 8자리: ${SECRET:0:8}...)"

exec java -jar /usr/share/jenkins/agent.jar \
    -url "$MASTER_URL" \
    -secret "$SECRET" \
    -name "$AGENT_NAME" \
    -workDir "/home/jenkins/agent"

# ══════════════════════════════════════════════════════════════════════════════
# dataflow_vuln_scan — 应用镜像 (薄层, 随代码增量构建)
#
# FROM 稳定基础镜像 (Dockerfile.base 产物), 只含 pip 依赖 + 项目代码 + 配置。
# 基础层 (apt/node/pi-coding-agent/venv/patch) 在 base 镜像里, 不随代码重建。
#
# 构建: docker build -t ghcr.io/gaiasechw/secflow-app-dataflow-vuln-scan:latest .
# ══════════════════════════════════════════════════════════════════════════════

ARG BASE_IMAGE=ghcr.io/gaiasechw/secflow-app-dataflow-vuln-scan-base:latest
FROM ${BASE_IMAGE}

ARG SECFLOW_BUILD_VERSION=""

WORKDIR /opt/dataflow_vuln_scan

# ═══ Python deps (阿里云镜像; 仅 requirements.txt 变化时重跑, 否则缓存命中) ══
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir \
    --timeout 300 --retries 10 \
    -i https://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com \
    -r requirements.txt \
    && python3 -c "import tree_sitter, tree_sitter_c, tree_sitter_cpp; print('tree-sitter OK')" \
    && python3 -c "from pydantic import BaseModel; print('pydantic OK')"

# tree-sitter installed in venv; symlink to system python's site-packages
# so that pi's bash tool (uses system python3) can import tree-sitter
RUN for pkg in tree_sitter tree_sitter_c tree_sitter_cpp; do \
        src="/opt/venv/lib/python3.12/site-packages/$pkg"; \
        dst="/usr/local/lib/python3.12/dist-packages/$pkg"; \
        [ -d "$src" ] && [ ! -e "$dst" ] && ln -sf "$src" "$dst" || true; \
    done && \
    /usr/bin/python3 -c "import tree_sitter, tree_sitter_c, tree_sitter_cpp; print('system python tree-sitter OK')" || echo 'WARNING: system python tree-sitter link failed'

# ═══ cache-bust: 每次 commit 改变该层, 强制后续 COPY app/ 代码层重建 ══════
# (buildx GHA 缓存曾命中旧 app 层致 digest 不变; 此 ARG bust 代码层, pip 层仍缓存)
ARG CACHEBUST=""
RUN echo "cachebust=$CACHEBUST" > /opt/cachebust

# ═══ 项目代码 (随代码变更增量重建) ═════════════════════════════════════════
COPY app/               ./app/
COPY main.py     ./
COPY prompts/           ./prompts/
COPY scripts/           ./scripts/
COPY tools/             ./tools/
COPY bin/               ./bin/
COPY skills/            ./skills/
COPY extensions/        ./extensions/
COPY config.example.json .env.example ./

RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /opt/dataflow_vuln_scan/build_meta.json
RUN find . -name '*.sh' -exec sed -i 's/\r$//' {} + \
    && chmod +x scripts/*.sh 2>/dev/null || true \
    && chmod +x scripts/autonomous/*.py 2>/dev/null || true \
    && chmod +x bin/restricted/find bin/restricted/grep bin/restricted/cat 2>/dev/null || true \
    && ln -sf /opt/dataflow_vuln_scan/scripts/autonomous/read_function.py /usr/local/bin/read_function \
    && ln -sf /opt/dataflow_vuln_scan/scripts/autonomous/report_finding.py /usr/local/bin/report_finding \
    && ln -sf /opt/dataflow_vuln_scan/scripts/autonomous/checkpoint.py /usr/local/bin/checkpoint \
    && ln -sf /opt/dataflow_vuln_scan/scripts/autonomous/grep_function.py /usr/local/bin/grep_function

# 工具: extract_func / gen_dataflow / gen_tainted_list 供 Worker 调用
RUN cp tools/extract_func.py /usr/local/bin/extract_func \
    && chmod +x /usr/local/bin/extract_func \
    && cp tools/gen_dataflow.py /usr/local/bin/gen_dataflow \
    && chmod +x /usr/local/bin/gen_dataflow \
    && cp tools/gen_tainted_list.py /usr/local/bin/gen_tainted_list \
    && chmod +x /usr/local/bin/gen_tainted_list

# ═══ pi 配置目录 + skills ═══════════════════════════════════════════════════
COPY config/settings.json /root/.pi/agent/settings.json
RUN mkdir -p /root/.pi/agent/skills \
    && ln -sf /opt/dataflow_vuln_scan/skills/write-dataflow /root/.pi/agent/skills/write-dataflow \
    && ln -sf /opt/dataflow_vuln_scan/skills/write-taint-flow /root/.pi/agent/skills/write-taint-flow \
    && ln -sf /opt/dataflow_vuln_scan/skills/write-taint-graph /root/.pi/agent/skills/write-taint-graph \
    && ln -sf /opt/dataflow_vuln_scan/skills/mine-dataflow-vulnerability /root/.pi/agent/skills/mine-dataflow-vulnerability

# ═══ 挂载点 ═══════════════════════════════════════════════════════════════════
RUN mkdir -p /data/target /data/config /data/output /data/workspace /data/sessions

ENV PORT=3000
ENV OUTPUT_DIR=/data/output
ENV ARCHIVE_DIR=/data/output
ENV RESULT_DIR=/data/output
ENV SESSION_DIR=/data/sessions
ENV SECFLOW_EXTERNAL_PROBE_PROCESS=1
ENV SECFLOW_PROBE_PORT=18080
ENV SECFLOW_MAIN_PID_FILE=/tmp/secflow-main.pid
ENV SECFLOW_MAIN_STARTED_AT_FILE=/tmp/secflow-main.started_at
ENV SECFLOW_PROBE_STARTUP_GRACE_SECONDS=30
ENV SECFLOW_PROBE_SERVICE_NAME=secflow-app-dataflow-vuln-scan

EXPOSE 3000
EXPOSE 18080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:18080/healthz || exit 1

# ═══ 入口脚本 (tini 作 PID 1) ═════════════════════════════════════════════
COPY scripts/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]

CMD ["./scripts/start-with-probe.sh", "python3", "main.py"]

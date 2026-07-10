# ══════════════════════════════════════════════════════════════════════════════
# dataflow_vuln_scan — 完全自包含 Dockerfile (参考 secflow-app-system-analyse 构建方案)
#
# FROM 公开 ubuntu:24.04 (daocloud 镜像), 不依赖任何私有基础镜像。
# APT/npm/pip 全部走国内镜像加速; 基础层即含 kill/ps/strace 等调试工具。
# 构建: docker build -t dataflow_vuln_scan .
# ══════════════════════════════════════════════════════════════════════════════

FROM m.daocloud.io/docker.io/library/ubuntu:24.04

ARG SECFLOW_BUILD_VERSION=""
ARG PI_NPM_PACKAGE=@earendil-works/pi-coding-agent

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Shanghai
ENV PI_CODING_AGENT_DIR=/root/.pi/agent

# ═══ APT mirror + 系统工具 (含完整调试能力) ════════════════════════════════
RUN sed -i \
    -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
    -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
    /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null \
    || sed -i \
    -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
    -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
    /etc/apt/sources.list 2>/dev/null || true

RUN apt-get update && apt-get install -y \
        bash ca-certificates curl git gnupg ripgrep tini tzdata wget zip unzip xz-utils \
        jq file tree less vim-tiny findutils coreutils \
        procps psmisc iproute2 net-tools lsof strace ltrace htop netcat-openbsd \
        iputils-ping dnsutils \
        build-essential make cmake pkg-config \
        clang clang-tools llvm gdb cscope universal-ctags python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone

# ═══ Node.js 22 + pi-coding-agent (npmmirror 加速) ═══════════════════════════
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g --registry=https://registry.npmmirror.com "${PI_NPM_PACKAGE}" \
    && command -v pi && pi --version 2>/dev/null || command -v pi \
    && mkdir -p "${PI_CODING_AGENT_DIR}/bin" "${PI_CODING_AGENT_DIR}/skills" \
    && ln -sf "$(command -v rg)" "${PI_CODING_AGENT_DIR}/bin/rg"

# ═══ Python 3 + venv ════════════════════════════════════════════════════════
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"

# ═══ Python deps (阿里云镜像加速) ═══════════════════════════════════════════
WORKDIR /opt/dataflow_vuln_scan
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir \
    --timeout 300 --retries 10 \
    -i https://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com \
    -r requirements.txt \
    && python3 -c "import tree_sitter, tree_sitter_c, tree_sitter_cpp; print('tree-sitter OK')" \
    && python3 -c "from pydantic import BaseModel; print('pydantic OK')"

# ═══ pi agent openai-completions patch (maxTokens fallback, 防 MiniMax 默认 max_tokens 太低 → JSON 截断) ══
# 非致命: 路径/结构变化时告警跳过, 不阻断构建
RUN JS=$(npm root -g)/${PI_NPM_PACKAGE}/node_modules/@earendil-works/pi-ai/dist/api/openai-completions.js \
    && if [ -f "$JS" ]; then \
        sed -i 's/if (options?.maxTokens) {/const maxTokens = options?.maxTokens ?? (model.maxTokens > 0 ? model.maxTokens : undefined);\n    if (maxTokens !== undefined) {/' "$JS" \
        && sed -i 's/params.max_tokens = options.maxTokens;/params.max_tokens = maxTokens;/' "$JS" \
        && sed -i 's/params.max_completion_tokens = options.maxTokens;/params.max_completion_tokens = maxTokens;/' "$JS" \
        && echo 'patched openai-completions.js: maxTokens fallback to model.maxTokens'; \
    else \
        echo "::warning::openai-completions.js not found at $JS, skip patch"; \
    fi

# ═══ 项目代码 ═══════════════════════════════════════════════════════════════
WORKDIR /opt/dataflow_vuln_scan
COPY requirements.txt ./
# 容器运行时 PATH 优先 /opt/venv/bin，必须确保 pip 安装到同一个 Python 环境
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt -q \
    && /opt/venv/bin/python3 -c "import fastapi, uvicorn; print('fastapi=', fastapi.__version__)" \
    && /opt/venv/bin/python3 -c "import tree_sitter, tree_sitter_c, tree_sitter_cpp; print('tree-sitter OK')" \
    && /opt/venv/bin/python3 -c "from pydantic import BaseModel; print('pydantic OK')"
COPY app/               ./app/
COPY main.py     ./
COPY prompts/           ./prompts/
COPY scripts/           ./scripts/
COPY tools/             ./tools/
COPY bin/               ./bin/
COPY skills/            ./skills/
COPY config.example.json .env.example ./

RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /opt/dataflow_vuln_scan/build_meta.json
RUN find . -name '*.sh' -exec sed -i 's/\r$//' {} + \
    && chmod +x scripts/*.sh 2>/dev/null || true

# 安装工具：extract_func / gen_dataflow / gen_tainted_list 供 Worker 直接调用
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

RUN ln -sf "$(which rg)" "${PI_CODING_AGENT_DIR}/bin/rg" \
    && echo "ripgrep ready: $(rg --version | head -1)" \
    && for _cmd in \
        rg grep find head tail cat sed awk cut tr sort uniq wc xargs \
        ls stat file basename dirname readlink realpath \
        jq python3; \
    do \
        _target="$(command -v "$_cmd" 2>/dev/null)" && \
        [ -x "$_target" ] && \
        ln -sf "$_target" "${PI_CODING_AGENT_DIR}/bin/$_cmd" 2>/dev/null || true; \
    done

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

# ═══ 入口脚本 (tini 作 PID 1, 信号处理正确) ═══════════════════════════════
COPY scripts/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]

# 默认 REST API; worker/scheduler 通过 K8s command/args 覆盖
CMD ["./scripts/start-with-probe.sh", "python3", "main.py"]

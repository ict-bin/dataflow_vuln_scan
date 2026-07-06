ARG SECFLOW_PI_AGENT_RUNTIME_IMAGE=ghcr.io/runshine/secflow-base-pi-agent-runtime:20260602
FROM ${SECFLOW_PI_AGENT_RUNTIME_IMAGE}

ARG SECFLOW_BUILD_VERSION=""
ENV PYTHONUNBUFFERED=1

# 覆盖升级 pi agent 到 @earendil-works/pi-coding-agent (新版, compaction_end.result 为 dict)
# 基础镜像预装的是 @mariozechner/pi-coding-agent@0.73.1 (停更, compaction 格式不兼容)
RUN npm uninstall -g @mariozechner/pi-coding-agent 2>/dev/null || true \
    && npm install -g @earendil-works/pi-coding-agent@latest \
    && command -v pi && pi --version 2>/dev/null || command -v pi

# Patch: openai-completions buildParams 不 fallback 到 model.maxTokens → MiniMax API 默认 max_tokens 太低 → JSON 截断
RUN JS=$(npm root -g)/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/api/openai-completions.js \
    && sed -i 's/if (options?.maxTokens) {/const maxTokens = options?.maxTokens ?? (model.maxTokens > 0 ? model.maxTokens : undefined);\n    if (maxTokens !== undefined) {/' $JS \
    && sed -i 's/params.max_tokens = options.maxTokens;/params.max_tokens = maxTokens;/' $JS \
    && sed -i 's/params.max_completion_tokens = options.maxTokens;/params.max_completion_tokens = maxTokens;/' $JS \
    && echo 'patched openai-completions.js: maxTokens fallback to model.maxTokens' \
    && grep -n 'maxTokens' $JS | head -5

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        zip \
        unzip \
        xz-utils \
        file \
        jq \
        tree \
        less \
        vim-tiny \
        findutils \
        coreutils \
        procps \
        psmisc \
        lsof \
        net-tools \
        iproute2 \
        iputils-ping \
        dnsutils \
        build-essential \
        make \
        cmake \
        pkg-config \
        clang \
        clang-tools \
        llvm \
        gdb \
        cscope \
        universal-ctags \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ═══ 项目代码 ═════════════════════════════════════════════════════════════════
WORKDIR /opt/dataflow_vuln_scan
COPY requirements.txt ./
# 容器运行时 PATH 优先 /opt/venv/bin，必须确保 pip 安装到同一个 Python 环境
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt -q \
    && /opt/venv/bin/python3 -c "import tree_sitter, tree_sitter_c, tree_sitter_cpp; print('tree-sitter OK')" \
    && /opt/venv/bin/python3 -c "from pydantic import BaseModel; print('pydantic OK')"
COPY app/               ./app/
COPY main.py     ./
COPY prompts/           ./prompts/
COPY scripts/           ./scripts/
COPY tools/             ./tools/
COPY skills/            ./skills/
COPY config.example.json .env.example ./
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /opt/dataflow_vuln_scan/build_meta.json
RUN find . -name '*.sh' -exec sed -i 's/\r$//' {} + && chmod +x scripts/*.sh 2>/dev/null || true
# 安装工具：extract_func / gen_dataflow / gen_tainted_list 供 Worker 直接调用
RUN cp tools/extract_func.py /usr/local/bin/extract_func \
    && chmod +x /usr/local/bin/extract_func \
    && cp tools/gen_dataflow.py /usr/local/bin/gen_dataflow \
    && chmod +x /usr/local/bin/gen_dataflow \
    && cp tools/gen_tainted_list.py /usr/local/bin/gen_tainted_list \
    && chmod +x /usr/local/bin/gen_tainted_list

# ═══ pi 配置目录 ══════════════════════════════════════════════════════════════
# pi 的全局配置目录，models.json 放这里才能被 pi 识别
# 容器启动脚本会将 /data/config/models.json 链接到此处
ENV PI_CODING_AGENT_DIR=/root/.pi/agent
COPY config/settings.json /root/.pi/agent/settings.json
RUN mkdir -p /root/.pi/agent/bin \
    # 将 write-dataflow skill 安装到 pi 全局发现目录
    # ~/.pi/agent/skills/ 是 pi 全局 skill 目录，任何 cwd 都能发现
    && mkdir -p /root/.pi/agent/skills \
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
#
# /data/target  — 待分析文件（只读）
# /data/config  — config.json + models.json + prompts/（只读）
# /data/output  — 输出目录
#
RUN mkdir -p /data/target /data/config /data/output /data/workspace /data/sessions
# 不声明 VOLUME（避免匿名卷遮盖 bind mount）

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

# ═══ 入口脚本 ═════════════════════════════════════════════════════════════════
# 启动前自动链接 models.json（如果挂载了的话）
COPY scripts/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# 默认 REST API，覆盖: python3 main.py /data/config/config.json
CMD ["./scripts/start-with-probe.sh", "python3", "main.py"]

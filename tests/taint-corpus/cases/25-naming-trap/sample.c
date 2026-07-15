// 25 命名陷阱: safe_copy 名字像安全, 实际不校验长度 -> 仍危险 (不靠命名, 读源码/DAG 确认)
void safe_copy(char* dst, char* src, int len);  // 名字 safe, 实际无边界校验 (危险)
void f(char* user, int len) {
    char buf[64];
    safe_copy(buf, user, len);   // L2 sink: 名字 safe 但实际危险 -> 仍出 finding
}

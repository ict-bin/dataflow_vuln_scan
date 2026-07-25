// 28 跨入参 escape: data 污点 -> buf (另一个入参)
// 场景: B 有两个入参 buf 和 data, data 的污点写入 buf -> escape
// tracker 应找读 buf 的函数
void C(char* buf);
void B(char* buf, char* data) {  // L0 entry, taint=data; buf 是另一个入参
    memcpy(buf, data, 16);        // L1 escape: data 污点写入入参 buf 的字段 -> extern, carrier=buf
    C(buf);                        // L2 callee: C 读被污染的 buf
}

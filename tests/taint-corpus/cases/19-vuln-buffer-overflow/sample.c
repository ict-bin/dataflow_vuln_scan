// 19 真 vuln: buffer-overflow — memcpy(buf, src, len) 用污点 len 无边界校验
void memcpy_dangerous(char*, char*, int);
void f(char* src, int len) {        // taint=len (攻击者可控)
    char buf[64];
    memcpy_dangerous(buf, src, len); // L3 sink: len 未校验, buf 定长 64 -> heap/stack overflow
}
// 期望: 挖掘在 memcpy_dangerous 节点出 finding (buffer-overflow)

// 24 跨函数 vuln: source 在 A, sink 在 C, 中转 B. 各段拼接, 跨段去重 (sink 近者优先)
void use(char*);
void C(char* p) { use(p); }              // C: sink 在 C (use)
void B(char* m) { C(m); }                // B: 中转 (传给 C)
void A(char* src) { B(src); }            // A: source (src 外部可控)
// 挖掘触发: C 无传出点(use外部) -> 先挖 C (C 传 use). B 传出点{C}就绪 -> 挖 B. A 传出点{B}就绪 -> 挖 A.
// findings: C 段出 finding (sink 在 C, 离 sink 近). B 段候选指向同一 sink -> 跨段去重丢弃. A 段同理.

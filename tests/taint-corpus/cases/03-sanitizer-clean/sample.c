// 03 sanitizer 清洗: t = cleanse(t) 后 t 不再污点, use(t) 不应被污点触达
void use(char*);
char* cleanse(char*);
void f(char* t) {        // L0 entry, taint=t
    t = cleanse(t);      // L1 callee (cleanse), t 被清洗 -> prune sanitized
    use(t);              // L2 use 不在污点 DAG (t 已清洗, 不传播)
}

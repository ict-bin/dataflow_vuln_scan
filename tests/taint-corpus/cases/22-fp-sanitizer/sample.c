// 22 误报(sanitizer 清洗): t=cleanse(t) 后 use(t), 挖掘应丢弃 (prune sanitized)
char* cleanse(char*);
void use(char*);
void f(char* t) {
    t = cleanse(t);   // L1 清洗 -> check DAG (f 的 t 轮) prune sanitized
    use(t);           // L2 候选 sink, 但 t 已干净 -> 丢弃
}

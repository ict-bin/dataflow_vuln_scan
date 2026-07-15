// 07 extern global 逃逸: t -> 全局 g_cache
char* g_cache;
void use(char*);
void f(char* t) {          // L0 entry, taint=t
    g_cache = t;          // L1 escape: t 写入全局 g_cache (extern, subkind=global)
    use(t);               // L2 仍在污点 (escape 不清洗)
}

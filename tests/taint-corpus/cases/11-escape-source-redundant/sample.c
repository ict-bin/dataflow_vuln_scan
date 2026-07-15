// 11 escape-source 冗余回传: A 把 t 逃逸到 g_cache (A 是 escape 源头);
//    tracker 找到读者 B 读 g_cache 返回它 -> 回传 g_cache 给 A;
//    但 A 本函数已持有 g_cache (escape 源头) -> #11 skip, 不重分析 A
char* g_cache;
void use(char*);
char* B() { return g_cache; }      // B 读 g_cache (中继) 并 return
void A(char* t) {                 // A: taint=t
    g_cache = t;                  // L1 extern escape (A 是 g_cache 的源头)
}
// 流程: A escape g_cache -> escape_track -> tracker 找到 B 读 g_cache
//       -> B 分析: return g_cache (return 边) -> 回传 (A, g_cache)
//       -> A 已持有 g_cache (escape 源头, g_cache 在 A 的 DAG 里) -> #11 skip, 不触发 A 的新分析

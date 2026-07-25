// 30 escape carrier 去重: 同一 carrier 多行出现只触发一次 escape_track
// 场景: g_global 是全局变量, 多行写入同一全局 -> 只发一条 escape_track
int g_global;
void reader(int v);
void f(int t) {               // L0 entry, taint=t
    g_global = t;             // L1 escape: t -> g_global (carrier=g_global)
    g_global = t + 1;         // L2 escape: t -> g_global (carrier=g_global, 重复!)
    g_global = t * 2;         // L3 escape: t -> g_global (carrier=g_global, 重复!)
    reader(g_global);         // L4 callee: 传 g_global
}

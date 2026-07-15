// 26 return 边漏洞: 返回未净化污点至信任边界 (caller 当可信用) -> 本函数挖
char* get_input();   // 外部污点源
char* f() {
    char* t = get_input();   // L1 source
    return t;                 // L2 return 边: 返回未净化污点至 caller (信任边界)
}
// 挖掘: f 的 return 节点是 sink (返回未净化到边界) -> finding (本函数挖, Q3 return 归本函数)

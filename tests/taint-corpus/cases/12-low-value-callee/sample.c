// 12 低价值 callee 剪枝: log_debug(t) 无安全价值 -> prune low_value_callee, 不跟入; use(t) 正常跟入
void log_debug(int);   // 日志打印, 低价值
void use(int);
void f(int t) {        // taint=t
    log_debug(t);      // L1 callee: log_debug, prune low_value_callee (无 followup)
    use(t);            // L2 callee: use, 正常跟入
}

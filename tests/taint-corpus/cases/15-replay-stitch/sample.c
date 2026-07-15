// 15 已分析重放拼接: A1, A2 都调 B(t). B 只分析一次; A2 的 (B,t) 项命中已分析 -> 从已存 B DAG 重放下游
void use(int);
void B(int x) { use(x); }    // B: taint=x, 下游 use
void A1(int t) { B(t); }     // A1 先触发 (B, x) -> B 分析, 存 DAG
void A2(int t) { B(t); }     // A2 后触发 (B, x) -> 命中已分析 -> 不重分析, 重放 B 的 use 下游项
// 验证: B 只 analyze 一次 (try_reserve); B 的下游 (use, x) 因 (use,x) 也去重, 不重复分析

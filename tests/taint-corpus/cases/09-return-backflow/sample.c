// 09 return 回传: B 返回污点 x, A 接住 r=B(t) 后 use(r)
void use(int);
int B(int x) { return x; }     // B: return x (return 边 + 回传项)
int A(int t) {                  // A 第一轮: taint=t
    int r = B(t);               // L1 callee: t -> B
    // r 此时未知污点 (A 不预测 B 返回); 等 B 分析完回传 r, A 再以 r 起一轮
    use(r);                     // L2 仅在 A 的 r 轮出现
}

// 06 多污点参数: A 调 B(t, t), B 两参数都污点 -> 拆 2 队列项独立并行
void useX(int); void useY(int);
void B(int x, int y) { useX(x); useY(y); }
void A(int t) {              // A: taint=t
    B(t, t);                 // L1 callee, x 与 y 均由 t 污染 -> 2 个 followup
}

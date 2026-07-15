// 02 分支汇合 merge: r 在 if/else 两臂都赋值 t, use(r) 依赖两臂 -> r 节点多 parent
void use(int);
void f(int t) {          // L0 entry, taint=t
    int r;
    if (t > 0) {
        r = t;            // L2 inside, cond t>0  -> r(then)
    } else {
        r = t;            // L4 inside, cond t<=0 -> r(else)
    }
    use(r);               // L6 callee: r 依赖 node1+node2 (merge)
}

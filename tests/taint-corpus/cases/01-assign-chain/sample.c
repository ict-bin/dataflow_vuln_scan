// 01 赋值链: t -> a -> b -> use(b)
void use(int);
void f(int t) {          // L0 entry, taint=t
    int a = t;            // L1 inside: t->a
    int b = a;            // L2 inside: a->b
    use(b);               // L3 callee: b->use
}

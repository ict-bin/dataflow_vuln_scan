// 04 sanitizer 约束(guard, 非清洗): if(len>100) return 截断超长路径, use(len) 仅在 len<=100
void use(int);
void f(int len) {         // L0 entry, taint=len
    if (len > 100) return; // L1 check {len,>,100} + 截断超长路径
    use(len);             // L2 callee, cond len<=100
}

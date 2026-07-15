// 10 间接调用 函数指针: (*fp)(t) 经函数指针调用, sink_ref=指针表达式, indirect_track 解析真实函数
void real_handler(int);           // 真实处理函数 (tracker 解析 fp 注册点得到)
typedef void (*cb)(int);
cb fp;
void use(int);
void f(int t) {                   // taint=t
    (*fp)(t);                     // L1 callee: sink_ref=fp (指针表达式), 间接 -> indirect_track
    use(t);                       // L2 仍传播
}

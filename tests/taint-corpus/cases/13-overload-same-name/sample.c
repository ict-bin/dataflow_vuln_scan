// 13 overload 同名: foo(int) 与 foo(char*) 是不同 overload, foo(t) t=int -> 选 foo(int), func_id 区分
void useX(int); void useY(char*);
void foo(int x) { useX(x); }          // overload 1: foo(int)
void foo(char* y) { useY(y); }        // overload 2: foo(char*) -- 同名不同参数
void A(int t) {                       // taint=t (int)
    foo(t);                            // L1 callee: 按 arg 类型选 foo(int), sink_ref=foo(int)
}

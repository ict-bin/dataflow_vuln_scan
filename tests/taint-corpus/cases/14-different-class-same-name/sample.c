// 14 不同类同名: A::handle 与 B::handle 同名不同类, a->handle(t) 选 A::handle (限定名)
class A { public: void handle(int x); };
class B { public: void handle(int x); };
void use(int);
void f(A* a, int t) {            // a 类型=A, taint=t
    a->handle(t);               // L1 callee: sink_ref=A::handle (限定名, tree-sitter 据 a 类型补全)
}

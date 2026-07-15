// 16 复合条件: if(a->cmd==1 && b->flag) proc(t); else if(a->cmd==2) alt(t);
//              复合条件独立记录 (CondTerm Compound), 不拍平不拆边
struct s { int cmd; int flag; };
void proc(int); void alt(int);
void f(struct s* a, int t) {        // taint=t (a 非跟踪污点, 仅条件源)
    if (a->cmd == 1 && a->flag) proc(t);   // L2 callee: cond=Compound{AND,[a->cmd==1, a->flag!=0]}
    else if (a->cmd == 2) alt(t);          // L3 callee: cond=Atom{a->cmd,==,2}
}

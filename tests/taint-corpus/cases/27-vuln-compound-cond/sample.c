// 27 复合条件路径 sink: 仅在 a->cmd==1 && a->flag 分支下触发 sink (condition 在 DAG 边上)
struct s { int cmd; int flag; };
void dangerous(int);
void f(struct s* a, int x) {        // taint=x
    if (a->cmd == 1 && a->flag) dangerous(x);  // L2 sink 仅在复合条件分支
}

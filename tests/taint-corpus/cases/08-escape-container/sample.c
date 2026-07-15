// 08 container 逃逸: t -> p->data, p 挂入 head 队列
struct item { struct item* next; char* data; };
struct item* head;
void use(char*);
void f(char* t) {              // L0 entry, taint=t
    struct item* p = malloc(sizeof(*p));
    p->data = t;               // L2 t -> p->data (inside)
    enqueue(p, &head);         // L3 escape container: p (carrier) 经 enqueue (escape_via) 入 head
    use(t);                    // L4 仍传播
}

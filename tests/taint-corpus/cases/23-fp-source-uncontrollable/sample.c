// 23 误报(源不可控): data 来自内核/proc (不可控), memcpy(sink) 虽达但 D2 丢弃
void read_proc(char*);  // 读 /proc (内核生成, 不可控)
void memcpy_dangerous(char*, char*, int);
void f() {
    char buf[256];
    read_proc(buf);              // L1 source: buf 来自 /proc (不可控)
    memcpy_dangerous(buf, buf, 256); // L2 sink: buf 到达, 但源不可控
}

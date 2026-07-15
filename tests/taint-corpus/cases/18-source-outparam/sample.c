// 18 被动输入 out-param: read(fd, buf, n) 把外部数据写入 buf, buf 变污点
void use(char*);
int read(int, char*, int);
void f(int fd) {            // fd 可能污点, 但此处关注 buf 被动生成
    char buf[256];
    read(fd, buf, 256);      // L2 source 边: read 写 out-param buf -> buf 污点源
    use(buf);                // L3 callee: buf -> use
}

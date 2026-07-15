// 20 顺序依赖(清洗): check(msg) 清洗了 msg -> handler(msg) 无洞 (D3 mitigated)
//    正向建链按序: check 效应=清洗 -> handler 处 msg 干净 -> 丢弃
char* cleanse(char*);
void handler(char*);
char* check(char* m) { return cleanse(m); }   // check 清洗 msg (return cleansed)
void f(char* msg) {                   // taint=msg
    msg = check(msg);                 // L1 callee check: msg = check(msg), check 清洗 -> msg 干净
    handler(msg);                     // L2 callee handler: msg 已干净, handler 无洞
}

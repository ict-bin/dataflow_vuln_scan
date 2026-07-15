// 21 顺序依赖(未清洗): check(msg) 只是校验返回码不清洗 -> handler(msg) 有洞 (D3 通过)
//    正向建链: check 效应=不变(未清洗) -> handler 处 msg 仍污点 -> 出 finding
int check(char* m) { return (m != 0); }   // check 只判空, 不清洗 msg (msg 仍污点)
void handler(char*);
void f(char* msg) {                  // taint=msg (外部可控)
    if (check(msg)) {                // L1 callee check (只判空, msg 未清洗)
        handler(msg);                // L2 callee handler: msg 仍污点 -> sink 候选
    }
}

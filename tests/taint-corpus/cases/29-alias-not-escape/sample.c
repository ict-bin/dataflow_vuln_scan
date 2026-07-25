// 29 局部变量别名不是 escape: header = msg->header (局部), 写 header->xxx = inside
// 场景: 只有一个入参 msg, header 是从 msg->header 获取的局部变量
// 写 header->field 不是 escape (污点仍在 msg 结构内), 是 inside
void process(char* val);
void f(char* msg) {                    // L0 entry, taint=msg
    struct HEADER { char* field; int flag; };
    struct HEADER* header = (struct HEADER*)msg;  // L1 inside: msg -> header (局部变量, msg 的别名)
    header->field = msg;               // L2 inside: msg -> header->field (局部变量字段, 不是 escape)
    header->flag = 1;                  // L3 inside: 常量赋值, 无污点传播
    process(header->field);            // L4 callee: 传 header->field (= msg->field)
}

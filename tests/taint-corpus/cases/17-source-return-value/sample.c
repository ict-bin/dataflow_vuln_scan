// 17 污点来源=返回值: t 由 getenv() 返回值生成 (无入口污点参数, 函数内自生)
void use(char*);
char* getenv(const char*);
void f() {                  // 无污点入口参数
    char* t = getenv("X");   // L1 source 边: getenv 返回值 -> t (taint 源节点)
    use(t);                  // L2 callee: t -> use
}

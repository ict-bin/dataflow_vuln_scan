// 05 callee 透传: A 调 B(t), B 内 use(pkt)
void use(int);
void B(int pkt) { use(pkt); }   // B: taint=pkt (形参名归一)
void A(int t) {                 // A: taint=t
    B(t);                       // L1 callee, t -> B 的 pkt
}

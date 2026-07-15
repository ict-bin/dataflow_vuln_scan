"""dagflow 工作队列: BFS 跨函数跟踪, 多线程并行消费。

设计: docs/design-taint-analysis.md §9 (队列驱动, (func,taint) 只分析一次, 已分析重放下游)。
终止: 队列空 + 无在途 (inflight==0)。
"""
from __future__ import annotations
import logging, queue, threading

logger = logging.getLogger("dvs.dagflow.work_queue")


class WorkQueue:
    """线程安全工作队列 + 在途计数 (终止判定)。

    get() 原子地取项 + 增 inflight; done() 减 inflight (处理完 + 已发下游项后调)。
    idle = 队列空 + inflight==0。
    """

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._inflight = 0
        self._lock = threading.Lock()
        self._processed = 0   # 统计: 已处理项数

    def put(self, item) -> None:
        self._q.put(item)

    def get(self, timeout: float = 1.0):
        """取项 (原子增 inflight)。空且超时返回 None。"""
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        with self._lock:
            self._inflight += 1
        return item

    def done(self) -> None:
        """处理完一项 (含已发下游项) 后调。inflight 归 0 且队列空 = idle。"""
        with self._lock:
            self._inflight -= 1
            self._processed += 1
            self._q.task_done()

    @property
    def idle(self) -> bool:
        with self._lock:
            return self._inflight == 0 and self._q.empty()

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"inflight": self._inflight, "processed": self._processed, "pending": self._q.qsize()}


def run_workers(wq: WorkQueue, process_fn, n_workers: int = 4,
                cancel_event: threading.Event | None = None,
                max_items: int = 10000) -> None:
    """启动 n_workers 消费者; 每个循环 get -> process_fn(item) -> done。

    process_fn(item): 处理一项 (可能 wq.put 下游项)。异常被捕获记录 (不崩队列)。
    终止: get 超时 + idle -> 退出。max_items 安全上限防失控。
    """
    processed = [0]
    plock = threading.Lock()
    def _loop():
        while True:
            if cancel_event is not None and cancel_event.is_set():
                break
            with plock:
                if processed[0] >= max_items:
                    break
            if wq.idle:
                break
            item = wq.get(timeout=1.0)
            if item is None:
                # 超时: 再判 idle (可能别 worker 刚发完下游)
                if wq.idle:
                    break
                continue
            with plock:
                processed[0] += 1
            try:
                process_fn(item)
            except Exception as e:  # 不让单项异常崩队列
                logger.exception("work_queue process error: %s", e)
            finally:
                wq.done()

    threads = [threading.Thread(target=_loop, name=f"dagflow-wq-{i}", daemon=True)
               for i in range(max(1, n_workers))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

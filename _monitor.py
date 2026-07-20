import pymysql, sys, time

for tick in range(20):
    conn = pymysql.connect(host='mysql.sothothv2-ns.svc.cluster.local', port=3306, user='secflow', password='Huawei12' + chr(35) + chr(36), database='secflow', charset='utf8mb4')
    cur = conn.cursor()
    cur.execute("SELECT status FROM secflow_app_dvs_tasks WHERE task_id='dvs_3f92677875b3468c'")
    status = cur.fetchone()[0]
    conn.close()

    conn = pymysql.connect(host='mysql.sothothv2-ns.svc.cluster.local', port=3306, user='secflow', password='Huawei12' + chr(35) + chr(36), database='dvs_complete', charset='utf8mb4')
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM processed_taints WHERE task_id=%s", ('dvs_3f92677875b3468c',))
    pt = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM taints WHERE task_id=%s", ('dvs_3f92677875b3468c',))
    tt = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM propagations WHERE task_id=%s", ('dvs_3f92677875b3468c',))
    pp = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM orchestration WHERE task_id=%s", ('dvs_3f92677875b3468c',))
    oe = cur.fetchone()[0]
    conn.close()
    print('[%ds] status=%s pt=%d tt=%d pp=%d oe=%d' % (tick*30, status, pt, tt, pp, oe))
    if status in ('passed','completed_limited','failed','error'):
        break
    time.sleep(30)

#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sqlite3.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

typedef unsigned __int64 u64;
typedef unsigned int u32;
typedef unsigned short u16;

typedef enum { ST_UNKNOWN=0, ST_UP=1, ST_DOWN=2 } Status;

typedef struct Host {
    volatile LONG used;
    volatile LONG enabled;

    char name[64];
    char group[64];
    char subgroup[64];
    ULONG ip;

    volatile LONG interval_ms;
    volatile LONG timeout_ms;
    volatile LONG down_threshold;

    volatile LONG ok;
    volatile LONG fail;
    volatile LONG consec_fail;

    volatile LONG last_rtt;
    volatile LONG min_rtt;
    volatile LONG max_rtt;
    volatile LONG samples;
    volatile LONGLONG sum_rtt;

    volatile LONG st;
    volatile LONGLONG last_change_qpc;

    SRWLOCK hist_lock;
    u32* hist_t;
    u16* hist_r;
    u32 hist_cap, hist_pos, hist_count;

    volatile LONG sched_gen;
    volatile LONG queued;
} Host;

typedef struct SchedNode {
    int host_id;
    u64 due_qpc;
    LONG gen;
} SchedNode;

static LARGE_INTEGER g_qpf;
static HANDLE g_icmp = NULL;

static Host* g_hosts = NULL;
static int g_hosts_cap = 20000;
static volatile LONG g_n_hosts = 0;
static SRWLOCK g_hosts_lock;

static SchedNode* g_heap = NULL;
static int g_heap_n = 0;
static int g_heap_cap = 0;
static SRWLOCK g_sched_lock;

static u32 g_default_interval_ms = 1000;
static u32 g_default_timeout_ms = 1000;
static u32 g_default_down_threshold = 3;
static u32 g_history_len = 512;
static u32 g_http_port = 8080;
static const char* g_db_path = "icmpmon.db";
static volatile LONG g_db_enabled = 1;

static HANDLE g_con = NULL;

static __forceinline u64 qpc_now(void){ LARGE_INTEGER t; QueryPerformanceCounter(&t); return (u64)t.QuadPart; }
static __forceinline u64 ms_to_qpc(u32 ms){ return ((u64)ms * (u64)g_qpf.QuadPart) / 1000ULL; }
static __forceinline double qpc_to_sec(u64 dt){ return (double)dt / (double)g_qpf.QuadPart; }

static void sleep_until_qpc(u64 due){
    for(;;){
        u64 now = qpc_now();
        if(now >= due) return;
        u64 diff = due - now;
        DWORD ms = (DWORD)((diff * 1000ULL) / (u64)g_qpf.QuadPart);
        if(ms > 2) Sleep(ms - 2); else Sleep(0);
    }
}

static int is_space_a(char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; }

static char* trim_a(char* s){
    char* e;
    while(*s && is_space_a(*s)) s++;
    if(!*s) return s;
    e = s + strlen(s) - 1;
    while(e >= s && is_space_a(*e)){
        *e = 0;
        if(e == s) break;
        e--;
    }
    return s;
}

static int resolve_v4(const char* s, ULONG* out_ip){
    struct addrinfo hints, *ai = 0;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(s, 0, &hints, &ai) != 0 || !ai) return 0;
    *out_ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.S_un.S_addr;
    freeaddrinfo(ai);
    return 1;
}

static void host_reset_stats(Host* h){
    h->ok = h->fail = h->consec_fail = 0;
    h->last_rtt = 0;
    h->min_rtt = 0x7fffffff;
    h->max_rtt = 0;
    h->samples = 0;
    h->sum_rtt = 0;
    h->st = ST_UNKNOWN;
    h->last_change_qpc = 0;
    AcquireSRWLockExclusive(&h->hist_lock);
    h->hist_pos = h->hist_count = 0;
    if(h->hist_t) ZeroMemory(h->hist_t, sizeof(u32)*h->hist_cap);
    if(h->hist_r) ZeroMemory(h->hist_r, sizeof(u16)*h->hist_cap);
    ReleaseSRWLockExclusive(&h->hist_lock);
}

static void host_init_slot(Host* h){
    ZeroMemory(h, sizeof(*h));
    InitializeSRWLock(&h->hist_lock);
    h->hist_cap = g_history_len;
    h->hist_t = (u32*)calloc(g_history_len, sizeof(u32));
    h->hist_r = (u16*)calloc(g_history_len, sizeof(u16));
    h->used = 0;
    h->enabled = 1;
    h->sched_gen = 1;
    h->interval_ms = (LONG)g_default_interval_ms;
    h->timeout_ms = (LONG)g_default_timeout_ms;
    h->down_threshold = (LONG)g_default_down_threshold;
    host_reset_stats(h);
}

static int parse_host_line(char* line, char* group, char* subgroup, char* name, u32* interval_ms){
    char* p = trim_a(line);
    if(!*p || *p=='#') return 0;

    char* tok[4] = {0};
    int n = 0;
    tok[n++] = p;
    while(*p && n < 4){
        if(*p == ';'){
            *p = 0;
            tok[n++] = p + 1;
        }
        p++;
    }

    for(int i=0;i<n;i++) tok[i] = trim_a(tok[i]);

    if(n == 1){
        if(!*tok[0]) return 0;
        _snprintf_s(group, 64, _TRUNCATE, "Default");
        _snprintf_s(subgroup, 64, _TRUNCATE, "Main");
        _snprintf_s(name, 64, _TRUNCATE, "%s", tok[0]);
        *interval_ms = g_default_interval_ms;
        return 1;
    }
    if(n >= 3){
        if(!*tok[2]) return 0;
        _snprintf_s(group, 64, _TRUNCATE, "%s", tok[0]);
        _snprintf_s(subgroup, 64, _TRUNCATE, "%s", tok[1]);
        _snprintf_s(name, 64, _TRUNCATE, "%s", tok[2]);
        if(n >= 4){
            u32 v = (u32)strtoul(tok[3], 0, 10);
            *interval_ms = v ? v : g_default_interval_ms;
        }else *interval_ms = g_default_interval_ms;
        return 1;
    }
    return 0;
}

static int add_host(const char* name, const char* group, const char* subgroup, ULONG ip, u32 interval_ms, u32 timeout_ms, u32 down_thr){
    int id = -1;
    AcquireSRWLockExclusive(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        if(!g_hosts[i].used){ id = i+1; break; }
    }
    if(id > 0){
        Host* h = &g_hosts[id-1];
        h->used = 1;
        h->enabled = 1;
        h->ip = ip;
        _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name);
        _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", group && *group ? group : "Default");
        _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", subgroup && *subgroup ? subgroup : "Main");
        h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms);
        h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms);
        h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr);
        InterlockedIncrement(&h->sched_gen);
        host_reset_stats(h);
        InterlockedIncrement(&g_n_hosts);
    }
    ReleaseSRWLockExclusive(&g_hosts_lock);
    return id;
}

static int edit_host(int id, const char* name, const char* group, const char* subgroup, const char* addr, int set_interval, u32 interval_ms, int set_timeout, u32 timeout_ms, int set_down, u32 down_thr, int set_enabled, int enabled){
    if(id < 1 || id > g_hosts_cap) return 0;
    AcquireSRWLockExclusive(&g_hosts_lock);
    Host* h = &g_hosts[id-1];
    if(!h->used){ ReleaseSRWLockExclusive(&g_hosts_lock); return 0; }

    if(name && *name) _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name);
    if(group && *group) _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", group);
    if(subgroup && *subgroup) _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", subgroup);
    if(addr && *addr){
        ULONG ip;
        if(resolve_v4(addr, &ip)) h->ip = ip;
    }
    if(set_interval){ h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms); InterlockedIncrement(&h->sched_gen); }
    if(set_timeout){ h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms); }
    if(set_down){ h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr); }
    if(set_enabled){ h->enabled = enabled ? 1 : 0; InterlockedIncrement(&h->sched_gen); }
    ReleaseSRWLockExclusive(&g_hosts_lock);
    return 1;
}

static int load_hosts_file(const char* path){
    FILE* f = fopen(path, "rb");
    if(!f){ fprintf(stderr, "hosts: cannot open '%s'\n", path); return -1; }
    int n = 0;
    char line[512];
    while(fgets(line, sizeof(line), f)){
        char g[64], sg[64], name[64];
        u32 interval_ms;
        if(!parse_host_line(line, g, sg, name, &interval_ms)) continue;
        ULONG ip;
        if(!resolve_v4(name, &ip)) continue;
        if(add_host(name, g, sg, ip, interval_ms, g_default_timeout_ms, g_default_down_threshold) > 0) n++;
    }
    fclose(f);
    return n;
}

static __forceinline void hist_push(Host* h, u32 t_epoch, u16 rtt_code){
    AcquireSRWLockExclusive(&h->hist_lock);
    h->hist_t[h->hist_pos] = t_epoch;
    h->hist_r[h->hist_pos] = rtt_code;
    h->hist_pos = (h->hist_pos + 1u) % h->hist_cap;
    if(h->hist_count < h->hist_cap) h->hist_count++;
    ReleaseSRWLockExclusive(&h->hist_lock);
}

static __forceinline void hswap(SchedNode* a, SchedNode* b){ SchedNode t=*a; *a=*b; *b=t; }
static void heap_up(int i){
    while(i>0){ int p=(i-1)>>1; if(g_heap[p].due_qpc <= g_heap[i].due_qpc) break; hswap(&g_heap[p], &g_heap[i]); i=p; }
}
static void heap_dn(int i){
    for(;;){
        int l=i*2+1, r=l+1, m=i;
        if(l<g_heap_n && g_heap[l].due_qpc < g_heap[m].due_qpc) m=l;
        if(r<g_heap_n && g_heap[r].due_qpc < g_heap[m].due_qpc) m=r;
        if(m==i) break;
        hswap(&g_heap[m], &g_heap[i]); i=m;
    }
}
static void heap_push(SchedNode x){
    if(g_heap_n >= g_heap_cap) return;
    g_heap[g_heap_n] = x;
    heap_up(g_heap_n++);
}
static SchedNode heap_pop(void){
    SchedNode t = g_heap[0];
    g_heap[0] = g_heap[--g_heap_n];
    if(g_heap_n>0) heap_dn(0);
    return t;
}

typedef struct Task { int host_id; } Task;
static Task* g_task_q = NULL;
static LONG g_q_cap = 0;
static LONG g_q_head = 0;
static LONG g_q_tail = 0;
static LONG g_q_count = 0;
static SRWLOCK g_q_lock;
static HANDLE g_sem = NULL;

static int q_post(int host_id){
    int ok = 0;
    AcquireSRWLockExclusive(&g_q_lock);
    if(g_q_count < g_q_cap){
        g_task_q[g_q_tail].host_id = host_id;
        g_q_tail = (g_q_tail + 1) % g_q_cap;
        g_q_count++;
        ok = 1;
    }
    ReleaseSRWLockExclusive(&g_q_lock);
    if(ok) ReleaseSemaphore(g_sem, 1, NULL);
    return ok;
}
static int q_take(void){
    int id = 0;
    WaitForSingleObject(g_sem, INFINITE);
    AcquireSRWLockExclusive(&g_q_lock);
    if(g_q_count > 0){
        id = g_task_q[g_q_head].host_id;
        g_q_head = (g_q_head + 1) % g_q_cap;
        g_q_count--;
    }
    ReleaseSRWLockExclusive(&g_q_lock);
    return id;
}

/* DB */
typedef enum { DB_SAMPLE=1, DB_EVENT=2, DB_STOP=3 } DbType;
typedef struct DbMsg {
    SLIST_ENTRY e;
    DbType type;
    u32 ts;
    int host_id;
    int rtt_ms;
    int timeout_ms;
    int old_st;
    int new_st;
    char detail[64];
} DbMsg;

static SLIST_HEADER g_dbq;
static HANDLE g_dbsem = NULL;
static void db_post(DbMsg* m){ InterlockedPushEntrySList(&g_dbq, &m->e); ReleaseSemaphore(g_dbsem, 1, NULL); }
static DbMsg* db_take(void){ WaitForSingleObject(g_dbsem, INFINITE); return (DbMsg*)InterlockedPopEntrySList(&g_dbq); }

static void db_exec(sqlite3* db, const char* sql){
    char* err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if(rc != SQLITE_OK){ fprintf(stderr, "SQLite exec error: %s\n", err ? err : "(null)"); sqlite3_free(err); }
}

static void db_init(void){
    sqlite3* db = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return; }
    db_exec(db, "PRAGMA journal_mode=WAL;");
    db_exec(db,
        "CREATE TABLE IF NOT EXISTS hosts(host_id INTEGER PRIMARY KEY,name TEXT,ip TEXT,grp TEXT,subgrp TEXT,interval_ms INTEGER,timeout_ms INTEGER,down_threshold INTEGER,enabled INTEGER);"
        "CREATE TABLE IF NOT EXISTS samples(ts INTEGER,host_id INTEGER,rtt_ms INTEGER NULL,timeout_ms INTEGER);"
        "CREATE TABLE IF NOT EXISTS events(ts INTEGER,host_id INTEGER,old_status INTEGER,new_status INTEGER,detail TEXT);"
    );
    sqlite3_close(db);
}

static void db_sync_hosts(void){
    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return; }
    db_exec(db, "BEGIN;");
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO hosts(host_id,name,ip,grp,subgrp,interval_ms,timeout_ms,down_threshold,enabled) VALUES(?,?,?,?,?,?,?,?,?)", -1, &st, NULL);

    AcquireSRWLockShared(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        Host* h = &g_hosts[i];
        if(!h->used) continue;
        char ipbuf[32];
        struct in_addr ia; ia.S_un.S_addr = h->ip;
        _snprintf_s(ipbuf, sizeof(ipbuf), _TRUNCATE, "%s", inet_ntoa(ia));
        sqlite3_reset(st);
        sqlite3_bind_int(st, 1, i+1);
        sqlite3_bind_text(st, 2, h->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ipbuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, h->group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, h->subgroup, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, h->interval_ms);
        sqlite3_bind_int(st, 7, h->timeout_ms);
        sqlite3_bind_int(st, 8, h->down_threshold);
        sqlite3_bind_int(st, 9, h->enabled);
        sqlite3_step(st);
    }
    ReleaseSRWLockShared(&g_hosts_lock);

    db_exec(db, "COMMIT;");
    sqlite3_finalize(st);
    sqlite3_close(db);
}

static int db_load_hosts(void){
    sqlite3* db = NULL;
    sqlite3_stmt* st = NULL;
    int n = 0;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ if(db) sqlite3_close(db); return 0; }
    if(sqlite3_prepare_v2(db, "SELECT host_id,name,ip,grp,subgrp,interval_ms,timeout_ms,down_threshold,enabled FROM hosts ORDER BY host_id", -1, &st, NULL) != SQLITE_OK){ sqlite3_close(db); return 0; }

    AcquireSRWLockExclusive(&g_hosts_lock);
    while(sqlite3_step(st) == SQLITE_ROW){
        int id = sqlite3_column_int(st, 0);
        const unsigned char* name = sqlite3_column_text(st, 1);
        const unsigned char* iptxt = sqlite3_column_text(st, 2);
        const unsigned char* grp = sqlite3_column_text(st, 3);
        const unsigned char* sub = sqlite3_column_text(st, 4);
        int interval_ms = sqlite3_column_int(st, 5);
        int timeout_ms = sqlite3_column_int(st, 6);
        int down_thr = sqlite3_column_int(st, 7);
        int enabled = sqlite3_column_int(st, 8);

        if(id < 1 || id > g_hosts_cap) continue;
        Host* h = &g_hosts[id-1];
        ULONG ip = 0;
        if(iptxt && *iptxt){
            struct in_addr ia;
            if(InetPtonA(AF_INET, (const char*)iptxt, &ia) == 1) ip = ia.S_un.S_addr;
        }
        if(ip == 0){
            if(!resolve_v4((const char*)(name ? name : (const unsigned char*)""), &ip)) continue;
        }

        h->used = 1;
        h->enabled = enabled ? 1 : 0;
        h->ip = ip;
        _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name ? (const char*)name : "host");
        _snprintf_s(h->group, sizeof(h->group), _TRUNCATE, "%s", grp ? (const char*)grp : "Default");
        _snprintf_s(h->subgroup, sizeof(h->subgroup), _TRUNCATE, "%s", sub ? (const char*)sub : "Main");
        h->interval_ms = (LONG)(interval_ms < 50 ? 50 : interval_ms);
        h->timeout_ms = (LONG)(timeout_ms < 50 ? 50 : timeout_ms);
        h->down_threshold = (LONG)(down_thr < 1 ? 1 : down_thr);
        h->sched_gen = 1;
        h->queued = 0;
        host_reset_stats(h);
        InterlockedIncrement(&g_n_hosts);
        n++;
    }
    ReleaseSRWLockExclusive(&g_hosts_lock);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return n;
}

static DWORD WINAPI db_thread(void* _){
    (void)_;
    sqlite3* db = NULL;
    sqlite3_stmt* st_sample = NULL;
    sqlite3_stmt* st_event = NULL;
    if(sqlite3_open(g_db_path, &db) != SQLITE_OK){ InterlockedExchange(&g_db_enabled, 0); if(db) sqlite3_close(db); return 0; }
    sqlite3_prepare_v2(db, "INSERT INTO samples(ts,host_id,rtt_ms,timeout_ms) VALUES(?,?,?,?)", -1, &st_sample, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO events(ts,host_id,old_status,new_status,detail) VALUES(?,?,?,?,?)", -1, &st_event, NULL);
    db_exec(db, "BEGIN;");
    int batch = 0;
    for(;;){
        DbMsg* m = db_take();
        if(!m) continue;
        if(m->type == DB_STOP){ free(m); break; }
        if(m->type == DB_SAMPLE){
            sqlite3_reset(st_sample);
            sqlite3_bind_int(st_sample,1,m->ts);
            sqlite3_bind_int(st_sample,2,m->host_id);
            if(m->rtt_ms>=0) sqlite3_bind_int(st_sample,3,m->rtt_ms); else sqlite3_bind_null(st_sample,3);
            sqlite3_bind_int(st_sample,4,m->timeout_ms);
            sqlite3_step(st_sample);
        }else if(m->type == DB_EVENT){
            sqlite3_reset(st_event);
            sqlite3_bind_int(st_event,1,m->ts);
            sqlite3_bind_int(st_event,2,m->host_id);
            sqlite3_bind_int(st_event,3,m->old_st);
            sqlite3_bind_int(st_event,4,m->new_st);
            sqlite3_bind_text(st_event,5,m->detail,-1,SQLITE_TRANSIENT);
            sqlite3_step(st_event);
        }
        free(m);
        batch++;
        if(batch >= 1000){ db_exec(db, "COMMIT;"); db_exec(db, "BEGIN;"); batch = 0; }
    }
    db_exec(db, "COMMIT;");
    if(st_sample) sqlite3_finalize(st_sample);
    if(st_event) sqlite3_finalize(st_event);
    sqlite3_close(db);
    return 0;
}

static void db_emit_sample(int host_id, u32 ts, int rtt_ms, int timeout_ms){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1,sizeof(DbMsg)); if(!m) return;
    m->type = DB_SAMPLE; m->host_id = host_id; m->ts = ts; m->rtt_ms = rtt_ms; m->timeout_ms = timeout_ms;
    db_post(m);
}
static void db_emit_event(int host_id, u32 ts, int old_st, int new_st, const char* detail){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1,sizeof(DbMsg)); if(!m) return;
    m->type = DB_EVENT; m->host_id = host_id; m->ts = ts; m->old_st = old_st; m->new_st = new_st;
    _snprintf_s(m->detail,sizeof(m->detail),_TRUNCATE,"%s",detail?detail:"");
    db_post(m);
}

static void update_minmax(Host* h, u32 rtt){
    LONG cur = h->min_rtt;
    while((u32)cur > rtt){ if(InterlockedCompareExchange(&h->min_rtt,(LONG)rtt,cur)==cur) break; cur = h->min_rtt; }
    cur = h->max_rtt;
    while((u32)cur < rtt){ if(InterlockedCompareExchange(&h->max_rtt,(LONG)rtt,cur)==cur) break; cur = h->max_rtt; }
}

static DWORD WINAPI worker(void* _){
    (void)_;
    for(;;){
        int id = q_take();
        if(id <= 0) break;

        if(id < 1 || id > g_hosts_cap) continue;
        Host* h = &g_hosts[id-1];
        InterlockedExchange(&h->queued, 0);
        if(!h->used || !h->enabled) continue;

        ULONG ip = h->ip;
        int timeout_ms = h->timeout_ms;
        int down_thr = h->down_threshold;

        char payload[32];
        char replybuf[sizeof(ICMP_ECHO_REPLY)+32];
        ZeroMemory(payload,sizeof(payload));
        DWORD rc = IcmpSendEcho(g_icmp, ip, payload, (WORD)sizeof(payload), NULL, replybuf, sizeof(replybuf), timeout_ms);
        ICMP_ECHO_REPLY* rep = (ICMP_ECHO_REPLY*)replybuf;

        u64 now_q = qpc_now();
        u32 now_epoch = (u32)time(NULL);

        if(rc && rep->Status == IP_SUCCESS){
            u32 rtt = rep->RoundTripTime;
            InterlockedIncrement(&h->ok);
            InterlockedExchange(&h->consec_fail, 0);
            InterlockedExchange(&h->last_rtt, (LONG)rtt);
            InterlockedIncrement(&h->samples);
            InterlockedAdd64(&h->sum_rtt, (LONGLONG)rtt);
            update_minmax(h, rtt);
            hist_push(h, now_epoch, (u16)(rtt > 65534 ? 65534 : rtt));
            db_emit_sample(id, now_epoch, (int)rtt, timeout_ms);
            int prev = InterlockedExchange(&h->st, ST_UP);
            if(prev != ST_UP){
                InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                db_emit_event(id, now_epoch, prev, ST_UP, "up");
            }
        }else{
            LONG cf = InterlockedIncrement(&h->consec_fail);
            InterlockedIncrement(&h->fail);
            hist_push(h, now_epoch, 0xFFFFu);
            db_emit_sample(id, now_epoch, -1, timeout_ms);
            if((u32)cf >= (u32)down_thr){
                int prev = InterlockedExchange(&h->st, ST_DOWN);
                if(prev != ST_DOWN){
                    InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                    db_emit_event(id, now_epoch, prev, ST_DOWN, "down");
                }
            }
        }
    }
    return 0;
}

static const char* st_name(int s){ return s==ST_UP?"UP":(s==ST_DOWN?"DOWN":"UNK"); }
static void con_move(short x, short y){ COORD c; c.X=x; c.Y=y; SetConsoleCursorPosition(g_con, c); }
static void con_clear_all(void){
    CONSOLE_SCREEN_BUFFER_INFO csbi; DWORD n,w;
    if(!GetConsoleScreenBufferInfo(g_con,&csbi)) return;
    n=(DWORD)(csbi.dwSize.X*csbi.dwSize.Y);
    FillConsoleOutputCharacterA(g_con,' ',n,(COORD){0,0},&w);
    FillConsoleOutputAttribute(g_con,csbi.wAttributes,n,(COORD){0,0},&w);
}
static void render_console(void){
    u64 now = qpc_now();
    unsigned up=0, down=0, unk=0;
    for(int i=0;i<g_hosts_cap;i++) if(g_hosts[i].used){ int s=g_hosts[i].st; if(s==ST_UP) up++; else if(s==ST_DOWN) down++; else unk++; }
    con_move(0,0);
    printf("icmpmon hosts=%ld up=%u down=%u unk=%u web=http://127.0.0.1:%u/\n", g_n_hosts, up, down, unk, g_http_port);
    printf("%-4s %-20s %-10s %-10s %-5s %-6s %-6s %-6s %-6s\n","id","group","subgroup","host","st","int","tout","ok","fail");
    for(int i=0;i<g_hosts_cap;i++){
        Host* h=&g_hosts[i]; if(!h->used) continue;
        LONG minr = h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
        double since = h->last_change_qpc? qpc_to_sec(now-(u64)h->last_change_qpc):0;
        printf("%-4d %-20s %-10s %-10s %-5s %-6ld %-6ld %-6ld %-6ld last=%ld avg=%lld min/max=%ld/%ld since=%.0f\n",
            i+1,h->group,h->subgroup,h->name,st_name(h->st),h->interval_ms,h->timeout_ms,h->ok,h->fail,h->last_rtt,
            h->samples? (h->sum_rtt/h->samples):0,minr,h->max_rtt,since);
    }
}

/* HTTP */
static void send_all(SOCKET s, const char* p, int n){ while(n>0){ int k=send(s,p,n,0); if(k<=0)return; p+=k; n-=k; } }
static int starts_with(const char* a, const char* b){ while(*b){ if(*a++!=*b++) return 0; } return 1; }
static void http_reply_raw(SOCKET c, const char* ct, const char* body, int blen){
    char hdr[256]; int hl=_snprintf_s(hdr,sizeof(hdr),_TRUNCATE,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\n\r\n",ct,blen);
    send_all(c,hdr,hl); send_all(c,body,blen);
}
static void http_reply(SOCKET c, const char* ct, const char* body){ http_reply_raw(c,ct,body,(int)strlen(body)); }
static void http_err(SOCKET c, int code, const char* msg){
    char b[128], h[256];
    int bl=_snprintf_s(b,sizeof(b),_TRUNCATE,"%d %s",code,msg);
    int hl=_snprintf_s(h,sizeof(h),_TRUNCATE,"HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n",code,msg,bl);
    send_all(c,h,hl); send_all(c,b,bl);
}
static int parse_qs_id(const char* path){ const char* q=strchr(path,'?'); if(!q) return -1; q++; while(*q){ if(starts_with(q,"id=")){ return atoi(q+3);} q=strchr(q,'&'); if(!q) break; q++; } return -1; }

static void url_decode(char* s){
    char* d=s;
    while(*s){
        if(*s=='+'){ *d++=' '; s++; }
        else if(*s=='%' && s[1] && s[2]){ char h[3]={s[1],s[2],0}; *d++=(char)strtol(h,0,16); s+=3; }
        else *d++=*s++;
    }
    *d=0;
}
static int form_get(char* body, const char* key, char* out, int out_sz){
    int klen=(int)strlen(key);
    char* p=body;
    while(*p){
        if(!strncmp(p,key,klen) && p[klen]=='='){
            p += klen+1;
            char* e=strchr(p,'&');
            int n=e? (int)(e-p):(int)strlen(p);
            if(n>=out_sz) n=out_sz-1;
            memcpy(out,p,n); out[n]=0; url_decode(out); return 1;
        }
        p=strchr(p,'&'); if(!p) break; p++;
    }
    return 0;
}

static void serve_index(SOCKET c){
    const char* html =
        "<!doctype html><html><head><meta charset=utf-8><title>icmpmon</title>"
        "<style>body{font-family:system-ui;margin:16px}.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}.tab{padding:6px 10px;border:1px solid #bbb;border-radius:8px;cursor:pointer;background:#fff}.tab.active{background:#1f6feb;color:#fff;border-color:#1f6feb}.card{border:1px solid #ddd;padding:10px;border-radius:10px;margin-bottom:12px}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:6px;font-size:13px}.subhead{background:#f7f7f7;font-weight:600}.up{color:green}.down{color:#b00020}.unk{color:#666}</style></head><body>"
        "<h2>icmpmon</h2><div id=meta></div><div id=tabs class=tabs></div>"
        "<div class=card><h3>Add host</h3><form id=addf>"
        "Group <input name=group value='Default'> Subgroup <input name=subgroup value='Main'> Host/IP <input name=name required> "
        "Interval (ms) <input name=interval_ms type=number value=1000 min=50> Timeout (ms) <input name=timeout_ms type=number value=1000 min=50>"
        " <button>Add</button></form><div id=addmsg></div></div>"
        "<div class=card><h3>Excel (CSV)</h3><button onclick='location.href=\"/api/export.csv\"'>Export CSV</button> <input id=f type=file accept='.csv'> <button onclick='previewCsv()'>Подробнее</button> <button onclick='importCsv()'>Import CSV</button> <span id=impmsg></span><pre id=impdetail style='white-space:pre-wrap;max-height:220px;overflow:auto;background:#f8f8f8;padding:8px'></pre></div>"
        "<table><thead><tr><th>ID</th><th>Group</th><th>Subgroup</th><th>Host/IP</th><th>Status</th><th>Interval (ms)</th><th>Timeout (ms)</th><th>DownThr (fails)</th><th>Loss</th><th>Details</th></tr></thead><tbody id=tb></tbody></table>"
        "<script>"
        "let selectedGroup='';"
        "function enc(f){return new URLSearchParams(new FormData(f)).toString()}"
        "function drawTabs(list){let groups=[...new Set(list.map(x=>x.group||'Default'))].sort();if(!selectedGroup&&groups.length)selectedGroup=groups[0];let tabs=document.getElementById('tabs');tabs.innerHTML='';for(let g of groups){let b=document.createElement('button');b.className='tab'+(g===selectedGroup?' active':'');b.textContent=g;b.onclick=()=>{selectedGroup=g;render(window._last)};tabs.appendChild(b);}}"
        "function render(j){window._last=j;document.getElementById('meta').textContent=`hosts=${j.hosts} up=${j.up} down=${j.down} unk=${j.unk}`;drawTabs(j.list);"
        "let tb=document.getElementById('tb');tb.innerHTML='';let arr=j.list.filter(h=>(h.group||'Default')===selectedGroup);arr.sort((a,b)=>(a.subgroup||'').localeCompare(b.subgroup||'')||a.id-b.id);let cur='';"
        "for(let h of arr){if(h.subgroup!==cur){cur=h.subgroup;let sh=document.createElement('tr');sh.className='subhead';sh.innerHTML=`<td colspan=10>${selectedGroup} / ${cur||'Main'}</td>`;tb.appendChild(sh);}"
        "let cls=h.st=='UP'?'up':(h.st=='DOWN'?'down':'unk');let tr=document.createElement('tr');tr.innerHTML=`<td>${h.id}</td><td>${h.group}</td><td>${h.subgroup}</td><td>${h.name}<br><small>${h.ip||''}</small></td><td class='${cls}'>${h.st}</td><td>${h.interval_ms}</td><td>${h.timeout_ms}</td><td>${h.down_threshold}</td><td>${h.fail||0}</td><td><a href='/host?id=${h.id}'>Open</a></td>`;tb.appendChild(tr);}"
        "}"
        "async function go(){let r=await fetch('/api/hosts');let j=await r.json();render(j);}"
        "async function addHost(ev){ev.preventDefault();let r=await fetch('/api/host/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:enc(ev.target)});document.getElementById('addmsg').textContent=await r.text();go();}"
        "async function previewCsv(){let f=document.getElementById('f').files[0];if(!f)return;let txt=await f.text();let r=await fetch('/api/import/preview.csv',{method:'POST',headers:{'Content-Type':'text/csv'},body:txt});let j=await r.json();document.getElementById('impmsg').textContent=`can_import=${j.preview_can_import} bad=${j.bad} dup_existing=${j.duplicates_existing} dup_file=${j.duplicates_file}`;let lines=(j.details||[]).map(d=>`line ${d.line}: ${d.host||'(empty)'} -> ${d.reason}`);document.getElementById('impdetail').textContent=lines.length?lines.join('\n'):'No conflicts';}"
        "async function importCsv(){let f=document.getElementById('f').files[0];if(!f)return;let txt=await f.text();let r=await fetch('/api/import.csv',{method:'POST',headers:{'Content-Type':'text/csv'},body:txt});document.getElementById('impmsg').textContent=await r.text();go();}"
        "document.getElementById('addf').onsubmit=addHost;go();setInterval(go,1500);"
        "</script></body></html>";
    http_reply(c, "text/html; charset=utf-8", html);
}

static void serve_api_hosts(SOCKET c){
    size_t cap = 8*1024 + (size_t)g_n_hosts * 512;
    char* buf=(char*)malloc(cap); if(!buf){ http_err(c,500,"oom"); return; }
    unsigned up=0,down=0,unk=0;
    int len=0;
    len += _snprintf_s(buf+len, cap-len, _TRUNCATE, "{\"hosts\":%ld,\"up\":", g_n_hosts);
    AcquireSRWLockShared(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++) if(g_hosts[i].used){ int s=g_hosts[i].st; if(s==ST_UP)up++; else if(s==ST_DOWN)down++; else unk++; }
    len += _snprintf_s(buf+len, cap-len, _TRUNCATE, "%u,\"down\":%u,\"unk\":%u,\"list\":[", up, down, unk);
    int first=1;
    for(int i=0;i<g_hosts_cap;i++){
        Host* h=&g_hosts[i];
        if(!h->used) continue;
        len += _snprintf_s(buf+len, cap-len, _TRUNCATE,
            "%s{\"id\":%d,\"name\":\"%s\",\"group\":\"%s\",\"subgroup\":\"%s\",\"st\":\"%s\",\"interval_ms\":%ld,\"timeout_ms\":%ld,\"down_threshold\":%ld,\"enabled\":%d}",
            first?"":",",i+1,h->name,h->group,h->subgroup,st_name(h->st),h->interval_ms,h->timeout_ms,h->down_threshold,h->enabled);
        first=0;
        if(len > (int)cap-1024) break;
    }
    ReleaseSRWLockShared(&g_hosts_lock);
    len += _snprintf_s(buf+len, cap-len, _TRUNCATE, "]}");
    http_reply_raw(c, "application/json; charset=utf-8", buf, (int)strlen(buf));
    free(buf);
}

static void serve_export_csv(SOCKET c){
    size_t cap = 1024 + (size_t)(g_n_hosts+4) * 256;
    char* buf = (char*)malloc(cap);
    if(!buf){ http_err(c,500,"oom"); return; }
    int len = _snprintf_s(buf, cap, _TRUNCATE, "group,subgroup,host,interval_ms,timeout_ms,down_threshold,enabled\r\n");
    AcquireSRWLockShared(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        Host* h=&g_hosts[i];
        if(!h->used) continue;
        len += _snprintf_s(buf+len, cap-len, _TRUNCATE, "\"%s\",\"%s\",\"%s\",%ld,%ld,%ld,%d\r\n", h->group, h->subgroup, h->name, h->interval_ms, h->timeout_ms, h->down_threshold, h->enabled);
        if(len > (int)cap-512) break;
    }
    ReleaseSRWLockShared(&g_hosts_lock);
    http_reply_raw(c, "text/csv; charset=utf-8", buf, (int)strlen(buf));
    free(buf);
}

static void strip_quotes(char* s){
    size_t n = strlen(s);
    if(n>=2 && s[0]=='"' && s[n-1]=='"'){ memmove(s, s+1, n-2); s[n-2]=0; }
}

static char* strip_utf8_bom(char* s){
    unsigned char* u = (unsigned char*)s;
    if(u[0]==0xEF && u[1]==0xBB && u[2]==0xBF) return s+3;
    return s;
}

static int split_csv_line(char* line, char delim, char** out, int max_out){
    int n = 0;
    char* p = line;
    while(*p && n < max_out){
        while(*p && is_space_a(*p)) p++;
        if(!*p) break;

        if(*p == '"'){
            p++;
            out[n++] = p;
            while(*p){
                if(*p == '"' && p[1] == '"'){
                    memmove(p, p+1, strlen(p));
                    p++;
                    continue;
                }
                if(*p == '"'){
                    *p = 0;
                    p++;
                    break;
                }
                p++;
            }
            while(*p && *p != delim) p++;
            if(*p == delim){ *p = 0; p++; }
        }else{
            out[n++] = p;
            while(*p && *p != delim) p++;
            if(*p == delim){ *p = 0; p++; }
        }
    }
    for(int i=0;i<n;i++){
        out[i] = trim_a(out[i]);
        strip_quotes(out[i]);
    }
    return n;
}


static int host_exists_name_or_ip(const char* name, ULONG ip){
    int found = 0;
    AcquireSRWLockShared(&g_hosts_lock);
    for(int i=0;i<g_hosts_cap;i++){
        Host* h = &g_hosts[i];
        if(!h->used) continue;
        if(ip != 0 && h->ip == ip){ found = 1; break; }
        if(name && *name && _stricmp(h->name, name) == 0){ found = 1; break; }
    }
    ReleaseSRWLockShared(&g_hosts_lock);
    return found;
}

static int in_batch_duplicate(const char* name, ULONG ip, ULONG* ips, char names[][64], int n){
    for(int i=0;i<n;i++){
        if(ip != 0 && ips[i] == ip) return 1;
        if(name && *name && _stricmp(names[i], name) == 0) return 1;
    }
    return 0;
}

static void append_detail_json(char* out, size_t cap, size_t* len, int line_no, const char* host, const char* reason, int* details_count){
    if(*details_count >= 200) return;
    *len += _snprintf_s(out+*len, cap-*len, _TRUNCATE,
        "%s{\"line\":%d,\"host\":\"%s\",\"reason\":\"%s\"}",
        (*details_count?",":""), line_no, host?host:"", reason?reason:"");
    (*details_count)++;
}

static void process_csv_rows(char* body, int preview_only, int* out_added, int* out_bad, int* out_dup_exist, int* out_dup_file, char* details, size_t details_cap, int* out_details_count){
    int added=0,bad=0,dup_exist=0,dup_file=0;
    size_t dlen = 0;
    int details_count = 0;
    int line_no = 0;

    ULONG* seen_ips = (ULONG*)calloc(g_hosts_cap, sizeof(ULONG));
    char (*seen_names)[64] = (char(*)[64])calloc(g_hosts_cap, sizeof(*seen_names));
    int seen_n = 0;

    char* save = NULL;
    char* line = strtok_s(body, "\r\n", &save);
    while(line){
        line_no++;
        char* t = strip_utf8_bom(trim_a(line));
        if(*t){
            if(starts_with(t, "group,") || starts_with(t, "group;") || starts_with(t, "GROUP,") || starts_with(t, "GROUP;")){
                line = strtok_s(NULL, "\r\n", &save);
                continue;
            }

            char delim = ',';
            if(strchr(t, ';') && !strchr(t, ',')) delim = ';';

            char* parts[8] = {0};
            int n = split_csv_line(t, delim, parts, 8);
            if(n>=3 && parts[2] && *parts[2]){
                ULONG ip;
                if(resolve_v4(parts[2], &ip)){
                    if(host_exists_name_or_ip(parts[2], ip)){
                        dup_exist++;
                        append_detail_json(details, details_cap, &dlen, line_no, parts[2], "already exists", &details_count);
                    }else if(in_batch_duplicate(parts[2], ip, seen_ips, seen_names, seen_n)){
                        dup_file++;
                        append_detail_json(details, details_cap, &dlen, line_no, parts[2], "duplicate inside file", &details_count);
                    }else if(!preview_only){
                        u32 iv = (n>3)?(u32)strtoul(parts[3],0,10):g_default_interval_ms;
                        u32 to = (n>4)?(u32)strtoul(parts[4],0,10):g_default_timeout_ms;
                        u32 dt = (n>5)?(u32)strtoul(parts[5],0,10):g_default_down_threshold;
                        int en = (n>6)?atoi(parts[6]):1;
                        int id = add_host(parts[2], (n>0)?parts[0]:"Default", (n>1)?parts[1]:"Main", ip, iv, to, dt);
                        if(id>0){
                            if(!en) edit_host(id,NULL,NULL,NULL,NULL,0,0,0,0,0,0,1,0);
                            AcquireSRWLockExclusive(&g_sched_lock);
                            SchedNode sn; sn.host_id=id; sn.gen=g_hosts[id-1].sched_gen; sn.due_qpc=qpc_now();
                            heap_push(sn);
                            ReleaseSRWLockExclusive(&g_sched_lock);
                            if(seen_n < g_hosts_cap){
                                seen_ips[seen_n] = ip;
                                _snprintf_s(seen_names[seen_n], 64, _TRUNCATE, "%s", parts[2]);
                                seen_n++;
                            }
                            added++;
                        }else{
                            bad++;
                            append_detail_json(details, details_cap, &dlen, line_no, parts[2], "cannot add (capacity?)", &details_count);
                        }
                    }else{
                        if(seen_n < g_hosts_cap){
                            seen_ips[seen_n] = ip;
                            _snprintf_s(seen_names[seen_n], 64, _TRUNCATE, "%s", parts[2]);
                            seen_n++;
                        }
                        added++;
                    }
                }else{
                    bad++;
                    append_detail_json(details, details_cap, &dlen, line_no, parts[2], "resolve failed", &details_count);
                }
            }else{
                bad++;
                append_detail_json(details, details_cap, &dlen, line_no, "", "invalid columns", &details_count);
            }
        }
        line = strtok_s(NULL, "\r\n", &save);
    }

    if(seen_ips) free(seen_ips);
    if(seen_names) free(seen_names);

    *out_added = added;
    *out_bad = bad;
    *out_dup_exist = dup_exist;
    *out_dup_file = dup_file;
    *out_details_count = details_count;
}

static void serve_import_preview_csv(SOCKET c, char* body){
    int add=0,bad=0,dup_exist=0,dup_file=0,details_count=0;
    char* details = (char*)calloc(1, 65536);
    if(!details){ http_err(c,500,"oom"); return; }
    process_csv_rows(body, 1, &add, &bad, &dup_exist, &dup_file, details, 65536, &details_count);

    char* out = (char*)calloc(1, 131072);
    if(!out){ free(details); http_err(c,500,"oom"); return; }
    _snprintf_s(out, 131072, _TRUNCATE,
        "{\"preview_can_import\":%d,\"bad\":%d,\"duplicates_existing\":%d,\"duplicates_file\":%d,\"details\":[%s]}",
        add, bad, dup_exist, dup_file, details);
    http_reply_raw(c, "application/json; charset=utf-8", out, (int)strlen(out));
    free(out);
    free(details);
}

static void serve_import_csv(SOCKET c, char* body){
    int added = 0, bad = 0, dup_exist = 0, dup_file = 0, details_count = 0;
    char* details = (char*)calloc(1, 65536);
    if(!details){ http_err(c,500,"oom"); return; }

    process_csv_rows(body, 0, &added, &bad, &dup_exist, &dup_file, details, 65536, &details_count);
    db_sync_hosts();

    char msg[160];
    _snprintf_s(msg,sizeof(msg),_TRUNCATE,"imported=%d bad=%d dup_existing=%d dup_file=%d",added,bad,dup_exist,dup_file);
    http_reply(c,"text/plain; charset=utf-8",msg);
    free(details);
}

static void serve_add_host(SOCKET c, char* body){
    char name[64]={0}, group[64]={0}, subgroup[64]={0}, tmp[32];
    if(!form_get(body,"name",name,sizeof(name)) || !*name){ http_err(c,400,"name required"); return; }
    form_get(body,"group",group,sizeof(group));
    form_get(body,"subgroup",subgroup,sizeof(subgroup));
    u32 interval=g_default_interval_ms, timeout=g_default_timeout_ms;
    if(form_get(body,"interval_ms",tmp,sizeof(tmp))) interval=(u32)strtoul(tmp,0,10);
    if(form_get(body,"timeout_ms",tmp,sizeof(tmp))) timeout=(u32)strtoul(tmp,0,10);
    ULONG ip;
    if(!resolve_v4(name,&ip)){ http_err(c,400,"cannot resolve host"); return; }
    int id=add_host(name,group,subgroup,ip,interval,timeout,g_default_down_threshold);
    if(id<=0){ http_err(c,500,"add failed"); return; }

    AcquireSRWLockExclusive(&g_sched_lock);
    SchedNode n; n.host_id=id; n.gen=g_hosts[id-1].sched_gen; n.due_qpc=qpc_now();
    heap_push(n);
    ReleaseSRWLockExclusive(&g_sched_lock);

    db_sync_hosts();
    http_reply(c,"text/plain; charset=utf-8","OK");
}

static void serve_edit_host(SOCKET c, int id, char* body){
    char name[64]={0}, group[64]={0}, subgroup[64]={0}, addr[64]={0}, tmp[32];
    int has_name=form_get(body,"name",name,sizeof(name));
    int has_group=form_get(body,"group",group,sizeof(group));
    int has_sub=form_get(body,"subgroup",subgroup,sizeof(subgroup));
    int has_addr=form_get(body,"addr",addr,sizeof(addr));
    int set_interval=0,set_timeout=0,set_down=0,set_enabled=0,enabled=1;
    u32 interval=0, timeout=0, down=0;
    if(form_get(body,"interval_ms",tmp,sizeof(tmp))){ set_interval=1; interval=(u32)strtoul(tmp,0,10); }
    if(form_get(body,"timeout_ms",tmp,sizeof(tmp))){ set_timeout=1; timeout=(u32)strtoul(tmp,0,10); }
    if(form_get(body,"down_threshold",tmp,sizeof(tmp))){ set_down=1; down=(u32)strtoul(tmp,0,10); }
    if(form_get(body,"enabled",tmp,sizeof(tmp))){ set_enabled=1; enabled=atoi(tmp)!=0; }

    if(!edit_host(id,has_name?name:NULL,has_group?group:NULL,has_sub?subgroup:NULL,has_addr?addr:NULL,set_interval,interval,set_timeout,timeout,set_down,down,set_enabled,enabled)){
        http_err(c,404,"host not found"); return;
    }

    if(set_interval || set_enabled){
        AcquireSRWLockExclusive(&g_sched_lock);
        Host* h=&g_hosts[id-1];
        SchedNode n; n.host_id=id; n.gen=h->sched_gen; n.due_qpc=qpc_now();
        heap_push(n);
        ReleaseSRWLockExclusive(&g_sched_lock);
    }

    db_sync_hosts();
    http_reply(c,"text/plain; charset=utf-8","OK");
}


static void serve_host_page(SOCKET c, int id){
    if(id<1 || id>g_hosts_cap || !g_hosts[id-1].used){ http_err(c,404,"not found"); return; }
    const char* html =
        "<!doctype html><html><head><meta charset=utf-8><title>host</title>"
        "<style>body{font-family:system-ui;margin:16px}.row{display:flex;gap:14px}.left{width:360px;border:1px solid #ddd;border-radius:10px;padding:10px}.right{flex:1;border:1px solid #ddd;border-radius:10px;padding:10px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0 10px 0}canvas{width:100%;height:460px;border:1px solid #ddd;background:#fff}#tip{position:fixed;display:none;background:#111;color:#fff;padding:6px 8px;border-radius:6px;font-size:12px;pointer-events:none;z-index:20}input,select,button{font-size:12px}</style></head><body>"
        "<a href='/'>← back</a><h2 id=t></h2><div class=row><div class=left><div id=left></div><hr><h4>Edit host</h4><form id=ef>"
        "Group <input name=group><br>Subgroup <input name=subgroup><br>"
        "Interval (ms) <input name=interval_ms type=number min=50><br>"
        "Timeout (ms) <input name=timeout_ms type=number min=50><br>"
        "Down threshold (fails) <input name=down_threshold type=number min=1><br>"
        "Enabled <select name=enabled><option value=1>on</option><option value=0>off</option></select><br><button>Save</button> <span id=emsg></span>"
        "</form></div><div class=right><div><b>RTT / Loss Timeline</b></div>"
        "<div class=toolbar>"
        "Window <select id=range><option value='60'>1m</option><option value='300' selected>5m</option><option value='900'>15m</option><option value='3600'>1h</option><option value='21600'>6h</option><option value='0'>All</option></select>"
        "<button id=liveBtn>Live: ON</button><button id=leftBtn>◀</button><button id=rightBtn>▶</button><button id=zoomInBtn>＋</button><button id=zoomOutBtn>－</button><button id=resetBtn>Reset</button>"
        "<label><input id=pauseHover type=checkbox checked> pause updates on hover</label>"
        "<span id=winInfo></span>"
        "</div><canvas id=cv width=1400 height=460></canvas></div></div><div id=tip></div>"
        "<script>"
        "const id=new URLSearchParams(location.search).get('id');"
        "let all=[];let view={live:true,start:0,end:0};let drag=null;let holdUpdates=false;let yMaxFixed=100;let formDirty=false;let formLocked=false;"
        "function fmt(ts){return new Date(ts*1000).toLocaleString()}"
        "function lossGapSec(intervalMs){let x=Math.ceil((intervalMs||1000)*2/1000);return x<1?1:x;}"
        "function computeFixedY(data){let m=1;for(let i=0;i<data.length;i++){if(data[i].rtt>=0&&data[i].rtt>m)m=data[i].rtt;}m=Math.ceil(m*1.15);if(m<50)m=50;return m;}"
        "function byRange(data){if(!data.length) return [];if(view.live){let sec=Number(document.getElementById('range').value);view.end=data[data.length-1].ts;view.start=(sec===0)?data[0].ts:Math.max(data[0].ts,view.end-sec);}return data.filter(x=>x.ts>=view.start&&x.ts<=view.end);}"
        "function setLive(v){view.live=v;document.getElementById('liveBtn').textContent='Live: '+(v?'ON':'OFF');}"
        "function stateOf(sample){return sample.rtt<0?'LOSS':'UP';}"
        "function draw(j){let cv=document.getElementById('cv');let g=cv.getContext('2d');g.clearRect(0,0,cv.width,cv.height);all=j.samples||[];if(!all.length){g.fillStyle='#666';g.fillText('No history yet. Wait for new samples...',20,30);return;}let d=byRange(all);if(!d.length)d=[all[all.length-1]];"
        "let pL=64,pR=20,pT=20,pB=36,W=cv.width,H=cv.height,plotW=W-pL-pR,plotH=H-pT-pB;let tMin=d[0].ts,tMax=d[d.length-1].ts;if(tMin===tMax)tMax=tMin+1;"
        "yMaxFixed = computeFixedY(all);"
        "let xAt=t=>pL+((t-tMin)/(tMax-tMin))*plotW;let yAt=v=>H-pB-((v/yMaxFixed)*plotH);let y0=yAt(0);"

        "g.strokeStyle='#eee';for(let i=0;i<=5;i++){let y=pT+i*(plotH/5);g.beginPath();g.moveTo(pL,y);g.lineTo(W-pR,y);g.stroke();let val=Math.round(yMaxFixed*(1-i/5));g.fillStyle='#666';g.fillText(val+' ms',8,y+4);}"
        "g.strokeStyle='#ddd';g.beginPath();g.moveTo(pL,pT);g.lineTo(pL,H-pB);g.lineTo(W-pR,H-pB);g.stroke();"

        "let pts=[];let step=Math.max(1,Math.ceil(d.length/2500));let arr=[];for(let i=0;i<d.length;i+=step)arr.push(d[i]);if(arr[arr.length-1]!==d[d.length-1])arr.push(d[d.length-1]);"
        "let missGap = lossGapSec(j.interval_ms||1000);"
        "for(let i=0;i<arr.length;i++){let s=arr[i];let x=xAt(s.ts);let y=(s.rtt>=0)?yAt(s.rtt):y0;pts.push({x,y,ts:s.ts,rtt:s.rtt,st:stateOf(s)});if(i===0) continue;let a=arr[i-1],b=arr[i];let xa=xAt(a.ts), xb=xAt(b.ts);let ya=(a.rtt>=0)?yAt(a.rtt):y0;let yb=(b.rtt>=0)?yAt(b.rtt):y0;let gap=b.ts-a.ts;"
        "if(gap>missGap){g.strokeStyle='#d4a017';g.beginPath();g.moveTo(xa,ya);g.lineTo(xa,y0);g.lineTo(xb,y0);g.lineTo(xb,yb);g.stroke();}"
        "else if(a.rtt<0 || b.rtt<0){g.strokeStyle='#c21807';g.beginPath();g.moveTo(xa,ya);g.lineTo(xb,yb);g.stroke();}"
        "else{g.strokeStyle='#0b65d8';g.beginPath();g.moveTo(xa,ya);g.lineTo(xb,yb);g.stroke();}"
        "}"
        "for(let i=0;i<pts.length;i++){let p=pts[i];if(p.st==='UP'){g.fillStyle='#1e6bd6';g.beginPath();g.arc(p.x,p.y,1.8,0,Math.PI*2);g.fill();}else{g.strokeStyle='#c21807';g.beginPath();g.moveTo(p.x,p.y-4);g.lineTo(p.x,p.y+4);g.stroke();}}"
        "window._pts=pts;"

        "let ticks=6;for(let i=0;i<=ticks;i++){let t=tMin+((tMax-tMin)*i/ticks);let x=xAt(t);g.strokeStyle='#f2f2f2';g.beginPath();g.moveTo(x,pT);g.lineTo(x,H-pB);g.stroke();g.fillStyle='#666';g.fillText(new Date(t*1000).toLocaleTimeString(),x-28,H-10);}"
        "document.getElementById('winInfo').textContent=`${fmt(tMin)} → ${fmt(tMax)} | points: ${d.length} | yMax: ${yMaxFixed}ms`;"
        "}"

        "function bindCanvas(){let cv=document.getElementById('cv'),tip=document.getElementById('tip');"
        "cv.onmouseenter=()=>{if(document.getElementById('pauseHover').checked) holdUpdates=true;};"
        "cv.onmouseleave=()=>{tip.style.display='none';holdUpdates=false;};"
        "cv.onmousedown=(e)=>{setLive(false);drag={x:e.clientX,start:view.start,end:view.end};};window.onmouseup=()=>drag=null;"
        "window.onmousemove=(e)=>{if(drag){let dx=e.clientX-drag.x;let span=Math.max(1,drag.end-drag.start);let dt=Math.round(-dx*(span/Math.max(1,cv.clientWidth)));view.start=drag.start+dt;view.end=drag.end+dt;draw(window._lastJ||{samples:all,interval_ms:1000});return;}"
        "let pts=window._pts||[];if(!pts.length)return;let r=cv.getBoundingClientRect();let x=(e.clientX-r.left)*(cv.width/r.width),y=(e.clientY-r.top)*(cv.height/r.height);let best=null,bd=1e9;for(let i=0;i<pts.length;i++){let p=pts[i],d=(p.x-x)*(p.x-x)+(p.y-y)*(p.y-y);if(d<bd){bd=d;best=p;}}if(!best||bd>250){tip.style.display='none';return;}tip.style.display='block';tip.innerHTML=`${fmt(best.ts)}<br>Status: ${best.st}<br>RTT: ${best.rtt<0?'loss':best.rtt+' ms'}`;let tw=tip.offsetWidth||140,th=tip.offsetHeight||70;let lx=e.clientX+14,ly=e.clientY+14;let maxX=window.innerWidth-tw-8,maxY=window.innerHeight-th-8;if(lx>maxX)lx=maxX;if(ly>maxY)ly=maxY;if(lx<8)lx=8;if(ly<8)ly=8;tip.style.left=lx+'px';tip.style.top=ly+'px';};"
        "cv.onwheel=(e)=>{e.preventDefault();setLive(false);let k=e.deltaY>0?1.2:0.82;let mid=(view.start+view.end)/2;let span=Math.max(2,(view.end-view.start)*k);view.start=Math.round(mid-span/2);view.end=Math.round(mid+span/2);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "}"

        "function bindToolbar(){"
        "document.getElementById('range').onchange=()=>{let sec=Number(document.getElementById('range').value);if(all.length){let e=all[all.length-1].ts;let s=(sec===0)?all[0].ts:Math.max(all[0].ts,e-sec);view.start=s;view.end=e;}setLive(true);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "document.getElementById('liveBtn').onclick=()=>{setLive(!view.live);if(view.live)go();};"
        "document.getElementById('leftBtn').onclick=()=>{setLive(false);let s=(view.end-view.start)||300;view.start-=Math.round(s*0.25);view.end-=Math.round(s*0.25);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "document.getElementById('rightBtn').onclick=()=>{setLive(false);let s=(view.end-view.start)||300;view.start+=Math.round(s*0.25);view.end+=Math.round(s*0.25);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "document.getElementById('zoomInBtn').onclick=()=>{setLive(false);let m=(view.start+view.end)/2,s=Math.max(2,(view.end-view.start)*0.7);view.start=Math.round(m-s/2);view.end=Math.round(m+s/2);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "document.getElementById('zoomOutBtn').onclick=()=>{setLive(false);let m=(view.start+view.end)/2,s=Math.max(2,(view.end-view.start)*1.4);view.start=Math.round(m-s/2);view.end=Math.round(m+s/2);draw(window._lastJ||{samples:all,interval_ms:1000});};"
        "document.getElementById('resetBtn').onclick=()=>{setLive(true);go();};"
        "}"

        "function fillEdit(j){if(formLocked||formDirty) return;let f=document.getElementById('ef');f.group.value=j.group;f.subgroup.value=j.subgroup;f.interval_ms.value=j.interval_ms;f.timeout_ms.value=j.timeout_ms;f.down_threshold.value=j.down_threshold;f.enabled.value=j.enabled?1:0;}"
        "async function go(){let r=await fetch('/api/host?id='+id);let j=await r.json();window._lastJ=j;if(!formLocked){document.getElementById('t').textContent=`#${j.id} ${j.name} (${j.ip})`;document.getElementById('left').innerHTML=`<b>Group/Subgroup:</b> ${j.group} / ${j.subgroup}<br><b>Status:</b> ${j.st}<br><b>OK:</b> ${j.ok} <b>Fail(loss):</b> ${j.fail}<br><b>Last:</b> ${j.last} ms<br><b>Avg:</b> ${j.avg} ms<br><b>Min/Max:</b> ${j.min}/${j.max} ms<br><b>Samples(all period):</b> ${j.samples_count}`;}if(!view.start||view.live){let sec=Number(document.getElementById('range').value);let end=(j.samples&&j.samples.length)?j.samples[j.samples.length-1].ts:Math.floor(Date.now()/1000);let start=(sec===0||!j.samples||!j.samples.length)?(j.samples&&j.samples.length?j.samples[0].ts:end-300):Math.max(j.samples[0].ts,end-sec);view.start=start;view.end=end;}fillEdit(j);draw(j);}"
        "document.getElementById('ef').onfocusin=()=>{formLocked=true;};document.getElementById('ef').oninput=()=>{formDirty=true;formLocked=true;};document.getElementById('ef').onsubmit=async (e)=>{e.preventDefault();let q=new URLSearchParams(new FormData(e.target)).toString();let r=await fetch('/api/host/edit?id='+id,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q});document.getElementById('emsg').textContent=await r.text();formDirty=false;formLocked=false;go();};"
        "bindCanvas();bindToolbar();go();setInterval(()=>{if(view.live && !holdUpdates) go();},2000);"
        "</script></body></html>";
    http_reply(c, "text/html; charset=utf-8", html);
}

static void serve_api_host(SOCKET c, int id){
    if(id<1 || id>g_hosts_cap || !g_hosts[id-1].used){ http_err(c,404,"not found"); return; }
    Host* h = &g_hosts[id-1];
    LONG ok=h->ok, fail=h->fail, last=h->last_rtt;
    LONG minr=h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
    LONG maxr=h->max_rtt;
    LONG samp=h->samples; LONGLONG sum=h->sum_rtt;
    u32 avg=(samp>0)?(u32)(sum/(u64)samp):0;
    struct in_addr ia; ia.S_un.S_addr = h->ip;
    char ipbuf[32]; _snprintf_s(ipbuf,sizeof(ipbuf),_TRUNCATE,"%s",inet_ntoa(ia));

    int n=0, cap=2048;
    int* ts=(int*)malloc(sizeof(int)*cap);
    int* rr=(int*)malloc(sizeof(int)*cap);
    if(!ts||!rr){ if(ts)free(ts); if(rr)free(rr); http_err(c,500,"oom"); return; }

    sqlite3* db=NULL; sqlite3_stmt* st=NULL;
    if(sqlite3_open(g_db_path,&db)==SQLITE_OK){
        sqlite3_prepare_v2(db, "SELECT ts,rtt_ms FROM samples WHERE host_id=? ORDER BY ts", -1, &st, NULL);
        sqlite3_bind_int(st,1,id);
        while(sqlite3_step(st)==SQLITE_ROW){
            if(n>=cap){ cap*=2; ts=(int*)realloc(ts,sizeof(int)*cap); rr=(int*)realloc(rr,sizeof(int)*cap); if(!ts||!rr) break; }
            ts[n]=sqlite3_column_int(st,0);
            rr[n]=(sqlite3_column_type(st,1)==SQLITE_NULL)?-1:sqlite3_column_int(st,1);
            n++;
            if(n>200000) break;
        }
    }
    if(st) sqlite3_finalize(st);
    if(db) sqlite3_close(db);

    size_t bcap = 8192u + (size_t)n*40u;
    char* buf=(char*)malloc(bcap);
    if(!buf){ free(ts); free(rr); http_err(c,500,"oom"); return; }
    size_t len=0;
    len += _snprintf_s(buf+len,bcap-len,_TRUNCATE,
        "{\"id\":%d,\"name\":\"%s\",\"ip\":\"%s\",\"group\":\"%s\",\"subgroup\":\"%s\",\"st\":\"%s\",\"ok\":%ld,\"fail\":%ld,\"last\":%ld,\"avg\":%u,\"min\":%ld,\"max\":%ld,\"interval_ms\":%ld,\"timeout_ms\":%ld,\"down_threshold\":%ld,\"enabled\":%d,\"samples_count\":%d,\"samples\":[",
        id,h->name,ipbuf,h->group,h->subgroup,st_name(h->st),ok,fail,last,avg,minr,maxr,h->interval_ms,h->timeout_ms,h->down_threshold,h->enabled,n);
    for(int i=0;i<n;i++){
        len += _snprintf_s(buf+len,bcap-len,_TRUNCATE,"%s{\"ts\":%d,\"rtt\":%d}", (i?",":""), ts[i], rr[i]);
        if(len > bcap-128) break;
    }
    len += _snprintf_s(buf+len,bcap-len,_TRUNCATE,"]}");
    http_reply_raw(c, "application/json; charset=utf-8", buf, (int)strlen(buf));
    free(buf); free(ts); free(rr);
}

static DWORD WINAPI http_thread(void* _){
    (void)_;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(ls == INVALID_SOCKET) return 0;
    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    struct sockaddr_in a; ZeroMemory(&a,sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((u_short)g_http_port);
    if(bind(ls,(struct sockaddr*)&a,sizeof(a))==SOCKET_ERROR || listen(ls,64)==SOCKET_ERROR){ closesocket(ls); return 0; }
    fprintf(stderr,"HTTP: http://127.0.0.1:%u/\n",g_http_port);

    for(;;){
        SOCKET c = accept(ls,NULL,NULL); if(c==INVALID_SOCKET) continue;
        char req[8192];
        int n=recv(c,req,sizeof(req)-1,0); if(n<=0){ closesocket(c); continue; }
        req[n]=0;

        char* body = strstr(req, "\r\n\r\n");
        int content_len = 0;
        char* cl = strstr(req, "Content-Length:");
        if(cl) content_len = atoi(cl + 15);
        if(body){ body += 4; }

        if(starts_with(req, "GET ")){
            char* p=req+4; char* sp=strchr(p,' ');
            if(!sp){ http_err(c,400,"bad"); }
            else{ *sp=0;
                if(strcmp(p,"/")==0) serve_index(c);
                else if(starts_with(p,"/host")) serve_host_page(c, parse_qs_id(p));
                else if(strcmp(p,"/api/hosts")==0) serve_api_hosts(c);
                else if(starts_with(p,"/api/host")) serve_api_host(c, parse_qs_id(p));
                else if(strcmp(p,"/api/export.csv")==0) serve_export_csv(c);
                else http_err(c,404,"not found");
            }
        }else if(starts_with(req,"POST ")){
            char* p=req+5; char* sp=strchr(p,' ');
            if(!sp || !body){ http_err(c,400,"bad"); }
            else{
                *sp=0;
                int have = n - (int)(body-req);
                while(have < content_len){
                    int r = recv(c, req+n, (int)sizeof(req)-1-n, 0);
                    if(r<=0) break;
                    n += r; req[n]=0; have = n - (int)(body-req);
                }
                if(strcmp(p,"/api/host/add")==0) serve_add_host(c, body);
                else if(starts_with(p,"/api/host/edit")) serve_edit_host(c, parse_qs_id(p), body);
                else if(strcmp(p,"/api/import.csv")==0) serve_import_csv(c, body);
                else if(strcmp(p,"/api/import/preview.csv")==0) serve_import_preview_csv(c, body);
                else http_err(c,404,"not found");
            }
        }else http_err(c,405,"method");

        closesocket(c);
    }
    return 0;
}

int main(int argc, char** argv){
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);

    int argi = 1;
    if(argc > 1 && (argv[1][0]<'0' || argv[1][0]>'9')) argi = 2; /* backward compatible: ignore hosts.txt arg */

    g_default_interval_ms = (argc>argi) ? (u32)strtoul(argv[argi],0,10) : 1000;
    int threads = (argc>argi+1)?atoi(argv[argi+1]):64;
    g_default_timeout_ms = (argc>argi+2)?(u32)strtoul(argv[argi+2],0,10):1000;
    g_default_down_threshold = (argc>argi+3)?(u32)strtoul(argv[argi+3],0,10):3;
    g_history_len = (argc>argi+4)?(u32)strtoul(argv[argi+4],0,10):512;
    g_http_port = (argc>argi+5)?(u32)strtoul(argv[argi+5],0,10):8080;
    u32 console_fps = (argc>argi+6)?(u32)strtoul(argv[argi+6],0,10):1;
    g_db_path = (argc>argi+7)?argv[argi+7]:"icmpmon.db";

    if(g_default_interval_ms < 50) g_default_interval_ms = 50;
    if(g_default_timeout_ms < 50) g_default_timeout_ms = 50;
    if(g_default_down_threshold < 1) g_default_down_threshold = 1;
    if(g_history_len < 16) g_history_len = 16;
    if(threads < 1) threads = 1;

    WSADATA w;
    if(WSAStartup(MAKEWORD(2,2), &w) != 0) return 1;
    QueryPerformanceFrequency(&g_qpf);

    InitializeSRWLock(&g_hosts_lock);
    InitializeSRWLock(&g_sched_lock);

    g_hosts = (Host*)calloc(g_hosts_cap, sizeof(Host));
    g_heap_cap = g_hosts_cap * 4;
    g_heap = (SchedNode*)calloc(g_heap_cap, sizeof(SchedNode));
    if(!g_hosts || !g_heap) return 1;
    for(int i=0;i<g_hosts_cap;i++) host_init_slot(&g_hosts[i]);

    int loaded = 0;

    g_icmp = IcmpCreateFile();
    if(g_icmp == INVALID_HANDLE_VALUE) return 1;

    InitializeSRWLock(&g_q_lock);
    g_q_cap = g_hosts_cap * 8;
    g_task_q = (Task*)calloc((size_t)g_q_cap, sizeof(Task));
    if(!g_task_q){ fprintf(stderr, "task queue alloc failed\n"); return 1; }
    g_sem = CreateSemaphoreW(NULL,0,0x7fffffff,NULL);
    InitializeSListHead(&g_dbq);
    g_dbsem = CreateSemaphoreW(NULL,0,0x7fffffff,NULL);

    db_init();
    loaded = db_load_hosts();
    fprintf(stderr,"loaded hosts from db: %d\n", loaded);
    db_sync_hosts();
    HANDLE hdb = CreateThread(NULL,0,db_thread,NULL,0,NULL);
    (void)hdb;

    int target_sweep_ms = 3000;
    LONG nh = g_n_hosts;
    int need_threads = (nh>0) ? (int)(((u64)nh * (u64)g_default_timeout_ms + target_sweep_ms - 1) / target_sweep_ms) : 1;
    if(need_threads < threads) need_threads = threads;
    if(need_threads > 1024) need_threads = 1024;
    threads = need_threads;
    fprintf(stderr, "workers: %d (auto-adjusted)\n", threads);
    for(int i=0;i<threads;i++) CreateThread(NULL,0,worker,NULL,0,NULL);
    CreateThread(NULL,0,http_thread,NULL,0,NULL);

    g_con = GetStdHandle(STD_OUTPUT_HANDLE);
    con_clear_all();

    u64 now = qpc_now();
    AcquireSRWLockExclusive(&g_sched_lock);
    for(int i=0;i<g_hosts_cap;i++) if(g_hosts[i].used){
        SchedNode n; n.host_id=i+1; n.gen=g_hosts[i].sched_gen; n.due_qpc=now;
        heap_push(n);
    }
    ReleaseSRWLockExclusive(&g_sched_lock);

    u64 render_step = ms_to_qpc(1000 / (console_fps?console_fps:1));
    if(render_step == 0) render_step = 1;
    u64 next_render = qpc_now() + render_step;

    for(;;){
        u64 wake = next_render;
        AcquireSRWLockShared(&g_sched_lock);
        if(g_heap_n > 0 && g_heap[0].due_qpc < wake) wake = g_heap[0].due_qpc;
        ReleaseSRWLockShared(&g_sched_lock);
        sleep_until_qpc(wake);

        now = qpc_now();
        if(now >= next_render){ do{ next_render += render_step; }while(next_render <= now); }

        for(;;){
            SchedNode sn;
            int have = 0;
            AcquireSRWLockExclusive(&g_sched_lock);
            if(g_heap_n > 0 && g_heap[0].due_qpc <= qpc_now()){ sn = heap_pop(); have = 1; }
            ReleaseSRWLockExclusive(&g_sched_lock);
            if(!have) break;
            if(sn.host_id < 1 || sn.host_id > g_hosts_cap) continue;

            Host* h = &g_hosts[sn.host_id-1];
            if(!h->used || sn.gen != h->sched_gen || !h->enabled) continue;

            if(InterlockedCompareExchange(&h->queued, 1, 0) == 0){
                if(!q_post(sn.host_id)) InterlockedExchange(&h->queued, 0);
            }

            u64 step = ms_to_qpc((u32)h->interval_ms);
            u64 next_due = sn.due_qpc + step;
            u64 tnow = qpc_now();
            while(next_due <= tnow) next_due += step;
            sn.due_qpc = next_due;
            AcquireSRWLockExclusive(&g_sched_lock);
            heap_push(sn);
            ReleaseSRWLockExclusive(&g_sched_lock);
        }
    }
    return 0;
}

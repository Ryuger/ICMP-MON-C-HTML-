/*
  icmpmon.c  (Windows, MSVC, C)

  Build (requires sqlite amalgamation рядом):
    cl /O2 /MT /TC icmpmon.c sqlite3.c /link ws2_32.lib iphlpapi.lib

  Run:
    icmpmon.exe hosts.txt 60 32 1000 3 256 8080 1 icmpmon.db

  Args:
    1 hosts.txt
    2 interval_sec
    3 threads
    4 timeout_ms
    5 down_threshold
    6 history_len
    7 http_port
    8 console_fps (1..5)
    9 db_path (e.g. icmpmon.db)
*/

#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sqlite3.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

typedef unsigned __int64 u64;
typedef unsigned int u32;
typedef unsigned short u16;

typedef enum { ST_UNKNOWN=0, ST_UP=1, ST_DOWN=2 } Status;

typedef struct Host {
    ULONG ip;               /* IPv4 network order */
    u64   next_due_qpc;     /* strict schedule */

    char  name[64];

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
    u32* hist_t;            /* epoch seconds */
    u16* hist_r;            /* rtt ms; 0xFFFF=loss */
    u32  hist_cap, hist_pos, hist_count;
} Host;

/* ---------------- Globals ---------------- */
static LARGE_INTEGER g_qpf;
static HANDLE g_icmp = NULL;

static u32 g_timeout_ms = 1000;
static u32 g_down_threshold = 3;

static Host* g_hosts = NULL;
static int   g_n_hosts = 0;
static u32   g_interval_sec = 0;
static u32   g_http_port = 8080;

static const char* g_db_path = "icmpmon.db";
static volatile LONG g_db_enabled = 1;

/* ---------------- QPC ---------------- */
static __forceinline u64 qpc_now(void){ LARGE_INTEGER t; QueryPerformanceCounter(&t); return (u64)t.QuadPart; }
static __forceinline u64 sec_to_qpc(u32 s){ return (u64)s * (u64)g_qpf.QuadPart; }
static __forceinline double qpc_to_sec(u64 dt){ return (double)dt / (double)g_qpf.QuadPart; }

static void sleep_until_qpc(u64 due){
    for(;;){
        u64 now = qpc_now();
        if(now >= due) return;
        u64 diff = due - now;
        DWORD ms = (DWORD)((diff * 1000ULL) / (u64)g_qpf.QuadPart);
        if(ms > 2) Sleep(ms - 2);
        else Sleep(0);
    }
}

/* ---------------- Helpers ---------------- */
static int is_space_a(char c){ return (c==' '||c=='\t'||c=='\r'||c=='\n'); }

static int resolve_v4(const char* s, ULONG* out_ip){
    struct addrinfo hints;
    struct addrinfo* ai = 0;
    int rc;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(s, 0, &hints, &ai);
    if(rc != 0 || !ai) return 0;
    *out_ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.S_un.S_addr;
    freeaddrinfo(ai);
    return 1;
}

static void host_init(Host* h, const char* name, ULONG ip, u32 history_len){
    ZeroMemory(h, sizeof(*h));
    h->ip = ip;
    h->st = ST_UNKNOWN;
    h->min_rtt = 0x7fffffff;
    _snprintf_s(h->name, sizeof(h->name), _TRUNCATE, "%s", name);

    InitializeSRWLock(&h->hist_lock);
    h->hist_cap = history_len;
    h->hist_t = (u32*)calloc(history_len, sizeof(u32));
    h->hist_r = (u16*)calloc(history_len, sizeof(u16));
    h->hist_pos = 0;
    h->hist_count = 0;
}

/* Read hosts.txt as ANSI/UTF-8/UTF-8 BOM/UTF-16LE BOM */
static int load_hosts_file(const char* path, Host* hosts, int max_hosts, u32 history_len){
    FILE* f = fopen(path, "rb");
    if(!f){ fprintf(stderr, "hosts: cannot open '%s'\n", path); return -1; }

    unsigned char b2[2];
    size_t r2 = fread(b2, 1, 2, f);
    if(r2 < 2){ fclose(f); return 0; }

    /* UTF-16LE BOM */
    if(b2[0]==0xFF && b2[1]==0xFE){
        int n = 0;
        for(;;){
            wchar_t wline[512];
            int wi = 0;

            for(;;){
                unsigned char b[2];
                if(fread(b,1,2,f) != 2) break;
                wchar_t wc = (wchar_t)(b[0] | (b[1]<<8));
                if(wc == L'\n') break;
                if(wc == L'\r') continue;
                if(wi < (int)(sizeof(wline)/sizeof(wline[0]))-1) wline[wi++] = wc;
            }
            if(wi==0 && feof(f)) break;
            wline[wi]=0;

            char line[512];
            int k = WideCharToMultiByte(CP_UTF8, 0, wline, -1, line, (int)sizeof(line), NULL, NULL);
            if(k<=0) continue;

            char* s = line;
            while(*s && is_space_a(*s)) s++;
            if(!*s) continue;
            char* e = s; while(*e && !is_space_a(*e)) e++;
            *e = 0;

            ULONG ip;
            if(!resolve_v4(s, &ip)) continue;

            host_init(&hosts[n], s, ip, history_len);
            n++;
            if(n>=max_hosts) break;

            if(feof(f)) break;
        }
        fclose(f);
        return n;
    }

    /* Not UTF-16LE: rewind and handle UTF-8 BOM optionally */
    fseek(f, 0, SEEK_SET);
    unsigned char b3[3];
    size_t r3 = fread(b3,1,3,f);
    if(!(r3==3 && b3[0]==0xEF && b3[1]==0xBB && b3[2]==0xBF)){
        fseek(f, 0, SEEK_SET);
    }

    int n = 0;
    char line[512];
    while(n < max_hosts && fgets(line, sizeof(line), f)){
        char* s = line;
        while(*s && is_space_a(*s)) s++;
        if(!*s) continue;
        char* e = s; while(*e && !is_space_a(*e)) e++;
        *e = 0;

        ULONG ip;
        if(!resolve_v4(s, &ip)) continue;

        host_init(&hosts[n], s, ip, history_len);
        n++;
    }
    fclose(f);
    return n;
}

/* ---------------- Heap schedule ---------------- */
static __forceinline void hswap(Host** a, Host** b){ Host* t=*a; *a=*b; *b=t; }
static void heap_up(Host** h, int i){
    while(i>0){
        int p=(i-1)>>1;
        if(h[p]->next_due_qpc <= h[i]->next_due_qpc) break;
        hswap(&h[p], &h[i]); i=p;
    }
}
static void heap_dn(Host** h, int n, int i){
    for(;;){
        int l=i*2+1, r=l+1, m=i;
        if(l<n && h[l]->next_due_qpc < h[m]->next_due_qpc) m=l;
        if(r<n && h[r]->next_due_qpc < h[m]->next_due_qpc) m=r;
        if(m==i) break;
        hswap(&h[m], &h[i]); i=m;
    }
}
static __forceinline void heap_push(Host** h, int* n, Host* x){ h[*n]=x; heap_up(h, (*n)++); }
static __forceinline Host* heap_pop(Host** h, int* n){ Host* t=h[0]; h[0]=h[--(*n)]; heap_dn(h,*n,0); return t; }

/* ---------------- Ping task queue ---------------- */
typedef struct Task { SLIST_ENTRY e; Host* h; } Task;
static SLIST_HEADER g_q;
static HANDLE g_sem = NULL;

static __forceinline void q_post(Host* h){
    Task* t = (Task*)_aligned_malloc(sizeof(Task), MEMORY_ALLOCATION_ALIGNMENT);
    if(!t) return;
    t->h = h;
    InterlockedPushEntrySList(&g_q, &t->e);
    ReleaseSemaphore(g_sem, 1, NULL);
}
static __forceinline Task* q_take(void){
    WaitForSingleObject(g_sem, INFINITE);
    return (Task*)InterlockedPopEntrySList(&g_q);
}

/* ---------------- History ring ---------------- */
static __forceinline void hist_push(Host* h, u32 t_epoch, u16 rtt_code){
    AcquireSRWLockExclusive(&h->hist_lock);
    h->hist_t[h->hist_pos] = t_epoch;
    h->hist_r[h->hist_pos] = rtt_code;
    h->hist_pos = (h->hist_pos + 1u) % h->hist_cap;
    if(h->hist_count < h->hist_cap) h->hist_count++;
    ReleaseSRWLockExclusive(&h->hist_lock);
}

/* ---------------- SQLite writer queue ---------------- */
typedef enum { DB_SAMPLE=1, DB_EVENT=2, DB_STOP=3 } DbType;

typedef struct DbMsg {
    SLIST_ENTRY e;
    DbType type;
    u32 ts;
    int host_id;
    int rtt_ms;      /* >=0 success, -1 loss */
    int timeout_ms;

    int old_st;
    int new_st;
    char detail[64];
} DbMsg;

static SLIST_HEADER g_dbq;
static HANDLE g_dbsem = NULL;

static __forceinline void db_post(DbMsg* m){
    InterlockedPushEntrySList(&g_dbq, &m->e);
    ReleaseSemaphore(g_dbsem, 1, NULL);
}
static __forceinline DbMsg* db_take(void){
    WaitForSingleObject(g_dbsem, INFINITE);
    return (DbMsg*)InterlockedPopEntrySList(&g_dbq);
}

static void db_exec(sqlite3* db, const char* sql){
    char* err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQLite exec error: %s\n", err ? err : "(null)");
        sqlite3_free(err);
    }
}

static void db_insert_hosts_sync(const char* db_path, Host* hosts, int n_hosts){
    sqlite3* db=NULL;
    sqlite3_stmt* st=NULL;

    if(sqlite3_open(db_path, &db) != SQLITE_OK){
        fprintf(stderr, "SQLite open (hosts insert) failed: %s\n", sqlite3_errmsg(db));
        if(db) sqlite3_close(db);
        return;
    }

    db_exec(db, "PRAGMA journal_mode=WAL;");
    db_exec(db, "PRAGMA synchronous=NORMAL;");
    db_exec(db,
        "CREATE TABLE IF NOT EXISTS hosts ("
        " host_id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " ip TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS samples ("
        " ts INTEGER NOT NULL,"
        " host_id INTEGER NOT NULL,"
        " rtt_ms INTEGER NULL,"
        " timeout_ms INTEGER NOT NULL,"
        " FOREIGN KEY(host_id) REFERENCES hosts(host_id)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_samples_host_ts ON samples(host_id, ts);"
        "CREATE TABLE IF NOT EXISTS events ("
        " ts INTEGER NOT NULL,"
        " host_id INTEGER NOT NULL,"
        " old_status INTEGER NOT NULL,"
        " new_status INTEGER NOT NULL,"
        " detail TEXT,"
        " FOREIGN KEY(host_id) REFERENCES hosts(host_id)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host_id, ts);"
    );

    db_exec(db, "BEGIN;");
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO hosts(host_id,name,ip) VALUES(?,?,?)", -1, &st, NULL);

    for(int i=0;i<n_hosts;i++){
        char ipbuf[32];
        struct in_addr ia; ia.S_un.S_addr = hosts[i].ip;
        const char* ipstr = inet_ntoa(ia);
        _snprintf_s(ipbuf, sizeof(ipbuf), _TRUNCATE, "%s", ipstr ? ipstr : "0.0.0.0");

        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(st, 1, i+1);
        sqlite3_bind_text(st, 2, hosts[i].name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ipbuf, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
    }

    db_exec(db, "COMMIT;");
    sqlite3_finalize(st);
    sqlite3_close(db);
}

static DWORD WINAPI db_thread(void* _){
    (void)_;
    sqlite3* db = NULL;
    sqlite3_stmt* st_sample = NULL;
    sqlite3_stmt* st_event  = NULL;

    int rc = sqlite3_open(g_db_path, &db);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQLite open failed: %s\n", sqlite3_errmsg(db));
        if(db) sqlite3_close(db);
        InterlockedExchange(&g_db_enabled, 0);
        return 0;
    }

    db_exec(db, "PRAGMA journal_mode=WAL;");
    db_exec(db, "PRAGMA synchronous=NORMAL;");
    db_exec(db, "PRAGMA temp_store=MEMORY;");
    db_exec(db, "PRAGMA cache_size=-20000;");

    sqlite3_prepare_v2(db, "INSERT INTO samples(ts,host_id,rtt_ms,timeout_ms) VALUES(?,?,?,?)", -1, &st_sample, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO events(ts,host_id,old_status,new_status,detail) VALUES(?,?,?,?,?)", -1, &st_event, NULL);

    db_exec(db, "BEGIN;");
    const int BATCH_MAX = 2000;
    int batch = 0;
    u64 last_commit = qpc_now();
    u64 commit_every = sec_to_qpc(1);

    for(;;){
        DbMsg* m = db_take();
        if(!m) continue;

        if(m->type == DB_STOP){
            free(m);
            break;
        }

        if(m->type == DB_SAMPLE){
            sqlite3_reset(st_sample);
            sqlite3_clear_bindings(st_sample);
            sqlite3_bind_int(st_sample, 1, (int)m->ts);
            sqlite3_bind_int(st_sample, 2, (int)m->host_id);
            if(m->rtt_ms >= 0) sqlite3_bind_int(st_sample, 3, m->rtt_ms);
            else sqlite3_bind_null(st_sample, 3);
            sqlite3_bind_int(st_sample, 4, m->timeout_ms);
            sqlite3_step(st_sample);
            batch++;
        }else if(m->type == DB_EVENT){
            sqlite3_reset(st_event);
            sqlite3_clear_bindings(st_event);
            sqlite3_bind_int(st_event, 1, (int)m->ts);
            sqlite3_bind_int(st_event, 2, (int)m->host_id);
            sqlite3_bind_int(st_event, 3, (int)m->old_st);
            sqlite3_bind_int(st_event, 4, (int)m->new_st);
            sqlite3_bind_text(st_event, 5, m->detail, -1, SQLITE_TRANSIENT);
            sqlite3_step(st_event);
            batch++;
        }

        free(m);

        u64 now = qpc_now();
        if(batch >= BATCH_MAX || (now - last_commit) >= commit_every){
            db_exec(db, "COMMIT;");
            db_exec(db, "BEGIN;");
            batch = 0;
            last_commit = now;
        }
    }

    db_exec(db, "COMMIT;");
    if(st_sample) sqlite3_finalize(st_sample);
    if(st_event) sqlite3_finalize(st_event);
    sqlite3_close(db);
    return 0;
}

static __forceinline void db_emit_sample(int host_id, u32 ts, int rtt_ms){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1, sizeof(DbMsg));
    if(!m) return;
    m->type = DB_SAMPLE;
    m->host_id = host_id;
    m->ts = ts;
    m->rtt_ms = rtt_ms;
    m->timeout_ms = (int)g_timeout_ms;
    db_post(m);
}
static __forceinline void db_emit_event(int host_id, u32 ts, int old_st, int new_st, const char* detail){
    if(!g_db_enabled) return;
    DbMsg* m = (DbMsg*)calloc(1, sizeof(DbMsg));
    if(!m) return;
    m->type = DB_EVENT;
    m->host_id = host_id;
    m->ts = ts;
    m->old_st = old_st;
    m->new_st = new_st;
    _snprintf_s(m->detail, sizeof(m->detail), _TRUNCATE, "%s", detail ? detail : "");
    db_post(m);
}

/* ---------------- ICMP worker ---------------- */
static void update_minmax(Host* h, u32 rtt){
    LONG cur = h->min_rtt;
    while((u32)cur > rtt){
        if(InterlockedCompareExchange(&h->min_rtt, (LONG)rtt, cur) == cur) break;
        cur = h->min_rtt;
    }
    cur = h->max_rtt;
    while((u32)cur < rtt){
        if(InterlockedCompareExchange(&h->max_rtt, (LONG)rtt, cur) == cur) break;
        cur = h->max_rtt;
    }
}

static DWORD WINAPI worker(void* arg){
    Host* base = (Host*)arg;

    for(;;){
        Task* t = q_take();
        if(!t) continue;
        if(t->h == NULL){ _aligned_free(t); break; }

        Host* h = t->h;
        int host_id = (int)(h - base) + 1;

        char payload[32];
        char replybuf[sizeof(ICMP_ECHO_REPLY) + 32];
        DWORD rc;
        ICMP_ECHO_REPLY* rep;

        u64 now_q = qpc_now();
        u32 now_epoch = (u32)time(NULL);

        ZeroMemory(payload, sizeof(payload));
        rc = IcmpSendEcho(
            g_icmp, h->ip,
            payload, (WORD)sizeof(payload),
            NULL,
            replybuf, sizeof(replybuf),
            g_timeout_ms
        );
        rep = (ICMP_ECHO_REPLY*)replybuf;

        if(rc && rep->Status == IP_SUCCESS){
            u32 rtt = rep->RoundTripTime;

            InterlockedIncrement(&h->ok);
            InterlockedExchange(&h->consec_fail, 0);
            InterlockedExchange(&h->last_rtt, (LONG)rtt);

            update_minmax(h, rtt);
            InterlockedIncrement(&h->samples);
            InterlockedAdd64(&h->sum_rtt, (LONGLONG)rtt);

            hist_push(h, now_epoch, (u16)((rtt > 65534u) ? 65534u : rtt));
            db_emit_sample(host_id, now_epoch, (int)rtt);

            int prev = InterlockedExchange(&h->st, ST_UP);
            if(prev != ST_UP){
                InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "rtt=%ums", (unsigned)rtt);
                db_emit_event(host_id, now_epoch, prev, ST_UP, d);
            }
        }else{
            LONG cf = InterlockedIncrement(&h->consec_fail);
            InterlockedIncrement(&h->fail);

            hist_push(h, now_epoch, 0xFFFFu);
            db_emit_sample(host_id, now_epoch, -1);

            if((u32)cf >= g_down_threshold){
                int prev = InterlockedExchange(&h->st, ST_DOWN);
                if(prev != ST_DOWN){
                    InterlockedExchange64(&h->last_change_qpc, (LONGLONG)now_q);
                    char d[64]; _snprintf_s(d, sizeof(d), _TRUNCATE, "fails=%ld", cf);
                    db_emit_event(host_id, now_epoch, prev, ST_DOWN, d);
                }
            }
        }

        _aligned_free(t);
    }
    return 0;
}

/* ---------------- Console rendering ---------------- */
static HANDLE g_con = NULL;

static void con_hide_cursor(void){
    CONSOLE_CURSOR_INFO ci;
    if(GetConsoleCursorInfo(g_con, &ci)){
        ci.bVisible = FALSE;
        SetConsoleCursorInfo(g_con, &ci);
    }
}
static void con_set_buffer_height(int rows){
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if(!GetConsoleScreenBufferInfo(g_con, &csbi)) return;
    COORD sz = csbi.dwSize;
    if(rows < 200) rows = 200;
    if(rows > 32760) rows = 32760;
    sz.Y = (SHORT)rows;
    SetConsoleScreenBufferSize(g_con, sz);
}
static void con_move(short x, short y){
    COORD c; c.X = x; c.Y = y;
    SetConsoleCursorPosition(g_con, c);
}
static void con_clear_all(void){
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD n, written;
    if(!GetConsoleScreenBufferInfo(g_con, &csbi)) return;
    n = (DWORD)(csbi.dwSize.X * csbi.dwSize.Y);
    FillConsoleOutputCharacterA(g_con, ' ', n, (COORD){0,0}, &written);
    FillConsoleOutputAttribute(g_con, csbi.wAttributes, n, (COORD){0,0}, &written);
    con_move(0,0);
}
static const char* st_name(int s){
    return (s==ST_UP) ? "UP" : (s==ST_DOWN) ? "DOWN" : "UNK";
}

static void render_full_list(Host* hosts, int n_hosts, u32 interval_sec, u32 http_port){
    u64 now_q = qpc_now();
    unsigned up=0, down=0, unk=0;
    for(int i=0;i<n_hosts;i++){
        int st = hosts[i].st;
        if(st==ST_UP) up++;
        else if(st==ST_DOWN) down++;
        else unk++;
    }

    con_move(0,0);

    char head[512];
    int hn = _snprintf_s(head, sizeof(head), _TRUNCATE,
        "icmpmon  interval=%us  timeout=%ums  down_thr=%u  hosts=%d  up=%u down=%u unk=%u   web=http://127.0.0.1:%u/\n"
        "db: %s   stop: Ctrl+C\n"
        "---------------------------------------------------------------------------------------------------------------\n"
        "#    host                             st    ok      fail    c_fail  last  avg   min/max   since(s)\n"
        "---------------------------------------------------------------------------------------------------------------\n",
        interval_sec, g_timeout_ms, g_down_threshold, n_hosts, up, down, unk, http_port, g_db_path
    );
    DWORD w=0; WriteConsoleA(g_con, head, (DWORD)hn, &w, NULL);

    for(int i=0;i<n_hosts;i++){
        Host* h = &hosts[i];

        LONG ok = h->ok, fail = h->fail, cf = h->consec_fail;
        LONG last = h->last_rtt;
        LONG minr = h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
        LONG maxr = h->max_rtt;
        LONG samp = h->samples; LONGLONG sum = h->sum_rtt;
        u32 avg = (samp>0) ? (u32)(sum / (u64)samp) : 0;

        double since = 0.0;
        LONGLONG lc = h->last_change_qpc;
        if(lc != 0) since = qpc_to_sec(now_q - (u64)lc);

        char line[256];
        int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "%-4d %-32s %-5s %-7ld %-7ld %-7ld %-5ld %-5u %4ld/%-4ld %-8.0f\n",
            i+1, h->name, st_name(h->st),
            ok, fail, cf,
            last, avg, minr, maxr, since
        );
        WriteConsoleA(g_con, line, (DWORD)n, &w, NULL);
    }
}

/* ---------------- HTTP server ---------------- */
static void send_all(SOCKET s, const char* p, int n){
    while(n>0){
        int k = send(s, p, n, 0);
        if(k<=0) return;
        p += k; n -= k;
    }
}
static int starts_with(const char* a, const char* b){
    while(*b){ if(*a++ != *b++) return 0; }
    return 1;
}
static int parse_qs_id(const char* path){
    const char* q = strchr(path, '?');
    if(!q) return -1;
    q++;
    while(*q){
        if(starts_with(q, "id=")){ q+=3; return atoi(q); }
        q = strchr(q, '&'); if(!q) break; q++;
    }
    return -1;
}
static void http_reply_raw(SOCKET c, const char* ct, const char* body, int blen){
    char hdr[256];
    int hl = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\n\r\n",
        ct, blen);
    send_all(c, hdr, hl);
    send_all(c, body, blen);
}
static void http_reply(SOCKET c, const char* ct, const char* body){
    http_reply_raw(c, ct, body, (int)strlen(body));
}
static void http_404(SOCKET c){
    const char* body="404";
    char hdr[128];
    int hl = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
        "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", (int)strlen(body));
    send_all(c, hdr, hl);
    send_all(c, body, (int)strlen(body));
}

static void serve_index(SOCKET c){
    const char* html =
        "<!doctype html><html><head><meta charset=utf-8><title>icmpmon</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:16px}table{border-collapse:collapse;width:100%}"
        "th,td{border-bottom:1px solid #ddd;padding:6px 8px;font-size:13px}tr:hover{background:#f7f7f7}"
        ".up{color:green}.down{color:#b00020}.unk{color:#666}</style></head><body>"
        "<h2>icmpmon</h2><div id=meta style='margin-bottom:10px'></div>"
        "<table><thead><tr><th>#</th><th>Host</th><th>Status</th><th>OK</th><th>Fail</th><th>Last</th><th>Avg</th><th>Min/Max</th></tr></thead>"
        "<tbody id=tb></tbody></table>"
        "<script>"
        "async function go(){"
        " let r=await fetch('/api/hosts'); if(!r.ok) throw new Error('api/hosts');"
        " let j=await r.json();"
        " document.getElementById('meta').textContent="
        "  `hosts=${j.hosts} up=${j.up} down=${j.down} unk=${j.unk} interval=${j.interval_sec}s timeout=${j.timeout_ms}ms down_thr=${j.down_threshold}`;"
        " let tb=document.getElementById('tb'); tb.innerHTML='';"
        " for(let h of j.list){"
        "  let cls=(h.st=='UP')?'up':(h.st=='DOWN')?'down':'unk';"
        "  let tr=document.createElement('tr');"
        "  tr.innerHTML=`<td>${h.id}</td><td><a href='/host?id=${h.id}'>${h.name}</a></td><td class='${cls}'>${h.st}</td>`+"
        "              `<td>${h.ok}</td><td>${h.fail}</td><td>${h.last}</td><td>${h.avg}</td><td>${h.min}/${h.max}</td>`;"
        "  tb.appendChild(tr);"
        " }"
        "}"
        "go().catch(e=>{document.getElementById('meta').textContent='API error: '+e;});"
        "setInterval(()=>go().catch(()=>{}),1000);"
        "</script></body></html>";
    http_reply(c, "text/html; charset=utf-8", html);
}

static void serve_host_page(SOCKET c, int id){
    if(id<1 || id>g_n_hosts){ http_404(c); return; }
    const char* html =
        "<!doctype html><html><head><meta charset=utf-8><title>host</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:16px}canvas{border:1px solid #ddd;width:100%;height:260px}"
        ".row{display:flex;gap:16px;flex-wrap:wrap}.card{border:1px solid #ddd;border-radius:10px;padding:12px;min-width:280px}"
        "</style></head><body>"
        "<a href='/'>← back</a><h2 id=title></h2>"
        "<div class=row>"
        "<div class=card><div id=stats></div></div>"
        "<div class=card style='flex:1'><div>RTT (blue) / Loss (red bars)</div><canvas id=cv width=1200 height=260></canvas></div>"
        "</div>"
        "<script>"
        "const id=new URLSearchParams(location.search).get('id');"
        "function draw(j){"
        " let cv=document.getElementById('cv'); let g=cv.getContext('2d');"
        " g.clearRect(0,0,cv.width,cv.height);"
        " let r=j.r; if(!r||r.length<2) return;"
        " let W=cv.width,H=cv.height,p=30;"
        " let max=0; for(let v of r){ if(v>=0 && v>max) max=v; } if(max<1) max=1;"
        " g.strokeStyle='#ddd'; g.beginPath(); g.moveTo(p,H-p); g.lineTo(W-p,H-p); g.lineTo(W-p,p); g.stroke();"
        " let xstep=(W-2*p)/(r.length-1);"
        " g.strokeStyle='#0078d4'; g.beginPath(); let first=true;"
        " for(let i=0;i<r.length;i++){ if(r[i]<0) continue; let x=p+i*xstep; let y=H-p-(r[i]/max)*(H-2*p);"
        "  if(first){ g.moveTo(x,y); first=false; } else g.lineTo(x,y); }"
        " g.stroke();"
        " g.fillStyle='#b00020';"
        " for(let i=0;i<r.length;i++){ if(r[i]<0){ let x=p+i*xstep; g.fillRect(x-1,p,2,H-2*p);} }"
        "}"
        "async function go(){"
        " let r=await fetch('/api/host?id='+id); if(!r.ok) throw new Error('api/host');"
        " let j=await r.json();"
        " document.getElementById('title').textContent=`#${j.id} ${j.name}`;"
        " document.getElementById('stats').innerHTML="
        "  `<b>Status:</b> ${j.st}<br>`+"
        "  `<b>OK:</b> ${j.ok} <b>Fail:</b> ${j.fail} <b>ConsecFail:</b> ${j.cfail}<br>`+"
        "  `<b>Last:</b> ${j.last} ms <b>Avg:</b> ${j.avg} ms <b>Min/Max:</b> ${j.min}/${j.max} ms<br>`+"
        "  `<b>History:</b> ${j.hist_count} samples`;"
        " draw(j);"
        "}"
        "go().catch(e=>{document.getElementById('stats').textContent='API error: '+e;});"
        "setInterval(()=>go().catch(()=>{}),1000);"
        "</script></body></html>";
    http_reply(c, "text/html; charset=utf-8", html);
}

static void serve_api_hosts(SOCKET c){
    unsigned up=0, down=0, unk=0;
    for(int i=0;i<g_n_hosts;i++){
        int st = g_hosts[i].st;
        if(st==ST_UP) up++;
        else if(st==ST_DOWN) down++;
        else unk++;
    }

    size_t cap = (size_t)g_n_hosts * 220u + 1024u;
    char* buf = (char*)malloc(cap);
    size_t len = 0;
    if(!buf){ http_404(c); return; }

    len += _snprintf_s(buf+len, cap-len, _TRUNCATE,
        "{\"hosts\":%d,\"up\":%u,\"down\":%u,\"unk\":%u,"
        "\"interval_sec\":%u,\"timeout_ms\":%u,\"down_threshold\":%u,\"list\":[",
        g_n_hosts, up, down, unk, g_interval_sec, g_timeout_ms, g_down_threshold
    );

    for(int i=0;i<g_n_hosts;i++){
        Host* h = &g_hosts[i];
        LONG ok = h->ok, fail = h->fail, last = h->last_rtt;
        LONG minr = h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
        LONG maxr = h->max_rtt;
        LONG samp = h->samples; LONGLONG sum = h->sum_rtt;
        u32 avg = (samp>0) ? (u32)(sum/(u64)samp) : 0;

        len += _snprintf_s(buf+len, cap-len, _TRUNCATE,
            "%s{\"id\":%d,\"name\":\"%s\",\"st\":\"%s\",\"ok\":%ld,\"fail\":%ld,\"last\":%ld,\"avg\":%u,\"min\":%ld,\"max\":%ld}",
            (i? ",":""), i+1, h->name, st_name(h->st), ok, fail, last, avg, minr, maxr
        );
        if(len > cap - 512) break;
    }

    len += _snprintf_s(buf+len, cap-len, _TRUNCATE, "]}");
    http_reply_raw(c, "application/json; charset=utf-8", buf, (int)strlen(buf));
    free(buf);
}

static void serve_api_host(SOCKET c, int id){
    if(id<1 || id>g_n_hosts){ http_404(c); return; }
    Host* h = &g_hosts[id-1];

    LONG ok = h->ok, fail = h->fail, cfail = h->consec_fail;
    LONG last = h->last_rtt;
    LONG minr = h->min_rtt; if((u32)minr==0x7fffffffU) minr=0;
    LONG maxr = h->max_rtt;
    LONG samp = h->samples; LONGLONG sum = h->sum_rtt;
    u32 avg = (samp>0) ? (u32)(sum/(u64)samp) : 0;

    u32 cap = h->hist_cap, count, pos;
    u32* tt = NULL; u16* rr = NULL;

    AcquireSRWLockShared(&h->hist_lock);
    count = h->hist_count;
    pos = h->hist_pos;
    if(count){
        tt = (u32*)malloc(sizeof(u32)*count);
        rr = (u16*)malloc(sizeof(u16)*count);
        if(tt && rr){
            u32 start = (pos + cap - count) % cap;
            for(u32 i=0;i<count;i++){
                u32 idx = (start + i) % cap;
                tt[i] = h->hist_t[idx];
                rr[i] = h->hist_r[idx];
            }
        }else{
            count = 0;
        }
    }
    ReleaseSRWLockShared(&h->hist_lock);

    size_t capj = 4096u + (size_t)count*36u;
    char* buf = (char*)malloc(capj);
    size_t len = 0;
    if(!buf){ if(tt)free(tt); if(rr)free(rr); http_404(c); return; }

    len += _snprintf_s(buf+len, capj-len, _TRUNCATE,
        "{\"id\":%d,\"name\":\"%s\",\"st\":\"%s\",\"ok\":%ld,\"fail\":%ld,\"cfail\":%ld,"
        "\"last\":%ld,\"avg\":%u,\"min\":%ld,\"max\":%ld,\"hist_count\":%u,\"t\":[",
        id, h->name, st_name(h->st), ok, fail, cfail, last, avg, minr, maxr, count
    );

    for(u32 i=0;i<count;i++){
        len += _snprintf_s(buf+len, capj-len, _TRUNCATE, "%s%u", (i? ",":""), tt[i]);
        if(len > capj-256) break;
    }

    len += _snprintf_s(buf+len, capj-len, _TRUNCATE, "],\"r\":[");
    for(u32 i=0;i<count;i++){
        int v = (rr[i]==0xFFFFu) ? -1 : (int)rr[i];
        len += _snprintf_s(buf+len, capj-len, _TRUNCATE, "%s%d", (i? ",":""), v);
        if(len > capj-256) break;
    }

    len += _snprintf_s(buf+len, capj-len, _TRUNCATE, "]}");
    http_reply_raw(c, "application/json; charset=utf-8", buf, (int)strlen(buf));

    free(buf);
    if(tt) free(tt);
    if(rr) free(rr);
}

static DWORD WINAPI http_thread(void* _){
    (void)_;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(ls == INVALID_SOCKET){
        fprintf(stderr, "HTTP: socket failed err=%d\n", WSAGetLastError());
        return 0;
    }

    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in a;
    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((u_short)g_http_port);

    if(bind(ls, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR){
        fprintf(stderr, "HTTP: bind 127.0.0.1:%u failed err=%d (port busy?)\n", g_http_port, WSAGetLastError());
        closesocket(ls);
        return 0;
    }
    if(listen(ls, 64) == SOCKET_ERROR){
        fprintf(stderr, "HTTP: listen failed err=%d\n", WSAGetLastError());
        closesocket(ls);
        return 0;
    }

    fprintf(stderr, "HTTP: listening on http://127.0.0.1:%u/\n", g_http_port);

    for(;;){
        SOCKET c = accept(ls, NULL, NULL);
        if(c == INVALID_SOCKET) continue;

        char req[4096];
        int n = recv(c, req, sizeof(req)-1, 0);
        if(n <= 0){ closesocket(c); continue; }
        req[n] = 0;

        if(starts_with(req, "GET ")){
            char* p = req + 4;
            char* sp = strchr(p, ' ');
            if(sp){
                *sp = 0;
                if(strcmp(p, "/") == 0) serve_index(c);
                else if(starts_with(p, "/host")) serve_host_page(c, parse_qs_id(p));
                else if(strcmp(p, "/api/hosts") == 0) serve_api_hosts(c);
                else if(starts_with(p, "/api/host")) serve_api_host(c, parse_qs_id(p));
                else http_404(c);
            }else http_404(c);
        }else http_404(c);

        closesocket(c);
    }
    return 0;
}

/* ---------------- main ---------------- */
int main(int argc, char** argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if(argc < 3){
        fprintf(stderr,
            "usage: %s hosts.txt interval_sec [threads=64] [timeout_ms=1000] [down_threshold=3] [history_len=512] [http_port=8080] [console_fps=1] [db_path=icmpmon.db]\n",
            argv[0]);
        return 2;
    }

    u32 interval_sec = (u32)strtoul(argv[2], 0, 10);
    int threads      = (argc > 3) ? (int)strtol(argv[3], 0, 10) : 64;
    g_timeout_ms     = (argc > 4) ? (u32)strtoul(argv[4], 0, 10) : 1000;
    g_down_threshold = (argc > 5) ? (u32)strtoul(argv[5], 0, 10) : 3;
    u32 history_len  = (argc > 6) ? (u32)strtoul(argv[6], 0, 10) : 512;
    g_http_port      = (argc > 7) ? (u32)strtoul(argv[7], 0, 10) : 8080;
    u32 console_fps  = (argc > 8) ? (u32)strtoul(argv[8], 0, 10) : 1;
    g_db_path        = (argc > 9) ? argv[9] : "icmpmon.db";

    if(interval_sec == 0){ fprintf(stderr, "interval_sec must be >0\n"); return 2; }
    if(threads < 1) threads = 1;
    if(threads > 256) threads = 256;
    if(g_down_threshold < 1) g_down_threshold = 1;
    if(history_len < 16) history_len = 16;
    if(history_len > 200000) history_len = 200000;
    if(g_http_port < 1 || g_http_port > 65535) g_http_port = 8080;
    if(console_fps < 1) console_fps = 1;
    if(console_fps > 5) console_fps = 5;

    WSADATA w;
    if(WSAStartup(MAKEWORD(2,2), &w) != 0){
        fprintf(stderr, "WSAStartup failed err=%d\n", WSAGetLastError());
        return 1;
    }
    QueryPerformanceFrequency(&g_qpf);

    g_hosts = (Host*)calloc(10000, sizeof(Host));
    Host** heap = (Host**)calloc(10000, sizeof(Host*));
    if(!g_hosts || !heap){
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    g_n_hosts = load_hosts_file(argv[1], g_hosts, 10000, history_len);
    if(g_n_hosts < 0) return 1;

    fprintf(stderr, "loaded hosts: %d\n", g_n_hosts);
    if(g_n_hosts == 0){
        fprintf(stderr, "no valid IPv4/DNS hosts loaded.\n");
        fprintf(stderr, "check that each line is a host and resolvable.\n");
        return 1;
    }

    /* show first few resolved */
    for(int i=0;i<g_n_hosts && i<5;i++){
        struct in_addr ia; ia.S_un.S_addr = g_hosts[i].ip;
        fprintf(stderr, "  #%d %s -> %s\n", i+1, g_hosts[i].name, inet_ntoa(ia));
    }

    g_interval_sec = interval_sec;

    g_icmp = IcmpCreateFile();
    if(g_icmp == INVALID_HANDLE_VALUE){
        fprintf(stderr, "IcmpCreateFile failed, err=%lu\n", GetLastError());
        return 1;
    }

    InitializeSListHead(&g_q);
    g_sem = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL);
    if(!g_sem){
        fprintf(stderr, "CreateSemaphore(ping) failed err=%lu\n", GetLastError());
        return 1;
    }

    InitializeSListHead(&g_dbq);
    g_dbsem = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL);
    if(!g_dbsem){
        fprintf(stderr, "CreateSemaphore(db) failed err=%lu\n", GetLastError());
        return 1;
    }

    /* DB schema + hosts */
    db_insert_hosts_sync(g_db_path, g_hosts, g_n_hosts);

    HANDLE hdb = CreateThread(NULL, 0, db_thread, NULL, 0, NULL);
    if(!hdb){
        fprintf(stderr, "DB thread create failed err=%lu (DB disabled)\n", GetLastError());
        InterlockedExchange(&g_db_enabled, 0);
    }else{
        fprintf(stderr, "SQLite: writing to %s\n", g_db_path);
    }

    /* worker pool */
    for(int i=0;i<threads;i++){
        HANDLE th = CreateThread(NULL, 0, worker, g_hosts, 0, NULL);
        if(!th) fprintf(stderr, "CreateThread(worker) failed err=%lu\n", GetLastError());
    }
    fprintf(stderr, "workers: %d\n", threads);

    /* HTTP server */
    HANDLE ht = CreateThread(NULL, 0, http_thread, NULL, 0, NULL);
    if(!ht) fprintf(stderr, "CreateThread(http) failed err=%lu\n", GetLastError());

    /* console */
    g_con = GetStdHandle(STD_OUTPUT_HANDLE);
    con_hide_cursor();
    con_set_buffer_height(g_n_hosts + 8);
    con_clear_all();

    /* schedule: spread first due across interval to avoid a spike */
    int n_heap = 0;
    u64 start = qpc_now();
    u64 step  = sec_to_qpc(interval_sec);
    for(int i=0;i<g_n_hosts;i++){
        u64 off = (u64)(((__int64)step * (__int64)i) / (__int64)g_n_hosts);
        g_hosts[i].next_due_qpc = start + off;
        heap_push(heap, &n_heap, &g_hosts[i]);
    }

    /* scheduler + render */
    u64 render_step = sec_to_qpc(1) / console_fps;
    if(render_step == 0) render_step = 1;
    u64 next_render = qpc_now() + render_step;

    for(;;){
        u64 due = heap[0]->next_due_qpc;
        u64 wake = (due < next_render) ? due : next_render;
        sleep_until_qpc(wake);

        /* render */
        {
            u64 t = qpc_now();
            if(t >= next_render){
                render_full_list(g_hosts, g_n_hosts, interval_sec, g_http_port);
                do { next_render += render_step; } while(next_render <= t);
            }
        }

        /* dispatch all due tasks */
        for(;;){
            u64 now = qpc_now();
            if(heap[0]->next_due_qpc > now) break;

            Host* h = heap_pop(heap, &n_heap);
            q_post(h);

            /* strict schedule: no drift */
            h->next_due_qpc += step;
            heap_push(heap, &n_heap, h);
        }
    }
    /* unreachable */
}

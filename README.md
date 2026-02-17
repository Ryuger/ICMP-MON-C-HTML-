# ICMP-MON-C-HTML-

ICMP мониторинг на C (Windows, MSVC) с веб-интерфейсом.

## Новые возможности
- Разделение хостов по `group/subgroup`.
- Добавление и редактирование хостов прямо из web UI.
- Индивидуальные параметры для каждого хоста:
  - `interval_ms`
  - `timeout_ms`
  - `down_threshold`
  - `enabled`
- Строгий per-host scheduler на `QueryPerformanceCounter` без дрейфа: для каждого хоста следующее время пинга рассчитывается от предыдущего дедлайна, а не от времени завершения запроса.

## Формат hosts.txt
Поддерживаются два формата строк:

1) Старый формат:
```
8.8.8.8
example.com
```

2) Новый формат:
```
Group;Subgroup;HostOrIP;IntervalMs
Core;Routers;192.168.1.1;250
DC1;Servers;srv-01.local;1000
```

## Сборка (MSVC)
```bat
cl /O2 /MT /TC icmpmon.c sqlite3.c /link ws2_32.lib iphlpapi.lib
```

## Запуск
```bat
icmpmon.exe hosts.txt 1000 64 1000 3 512 8080 1 icmpmon.db
```

Где:
- arg1: `hosts.txt`
- arg2: default `interval_ms`
- arg3: threads
- arg4: default `timeout_ms`
- arg5: default `down_threshold`
- arg6: history_len
- arg7: http_port
- arg8: console_fps
- arg9: sqlite db path

Веб интерфейс: `http://127.0.0.1:8080/`

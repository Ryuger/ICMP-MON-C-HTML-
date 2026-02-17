# ICMP-MON-C-HTML-

ICMP мониторинг на C (Windows, MSVC) с веб-интерфейсом.

## Что исправлено
- Группы/подгруппы хостов.
- Добавление/редактирование хостов в web UI.
- Excel-совместимый импорт/экспорт через CSV (`/api/export.csv`, `/api/import.csv`).
- `hosts.txt` теперь необязателен: можно запускать с `-` и работать полностью из web UI.
- Исправлен парсинг `\r\n`/пробелов в hosts файле.
- Очередь пингов переведена на FIFO (без LIFO-голодания), добавлен флаг `queued` на хост чтобы не копить дубликаты задач.
- Начальный опрос хостов стартует сразу (без растягивания первой волны), чтобы UNKNOWN быстрее переходил в UP/DOWN.
- Автоподбор числа worker-потоков под цель первичного прохода (~3 секунды) с верхним лимитом 1024.

## Формат hosts.txt
Поддерживаются строки:

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

## CSV для Excel
Колонки:
`group,subgroup,host,interval_ms,timeout_ms,down_threshold,enabled`

## Сборка (MSVC)
```bat
cl /O2 /MT /TC icmpmon.c sqlite3.c /link ws2_32.lib iphlpapi.lib
```

## Запуск
```bat
icmpmon.exe - 1000 64 1000 3 512 8080 1 icmpmon.db
```
или с файлом:
```bat
icmpmon.exe hosts.txt 1000 64 1000 3 512 8080 1 icmpmon.db
```

Веб интерфейс: `http://127.0.0.1:8080/`

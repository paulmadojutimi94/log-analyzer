# Log report: data/app\.log

9,847 entries from 10,581 lines, 2026-11-11T09:00:00.605000+00:00 to 2026-11-11T14:59:56.816000+00:00.

## At a glance

| Metric | Value |
|---|---|
| Errors (ERROR + CRITICAL + FATAL) | 481 |
| Distinct error groups | 13 |
| Error spikes | 3 |
| Malformed lines | 153 (1.45%) |
| Recovered (JSON lines, glued lines) | 21, 28 |
| Entries with unreadable bytes | 30 |
| Stack-trace lines attached | 580 |
| Analysis time | 0.086 s |

## Levels

| Level | Count | Share |
|---|---:|---:|
| INFO | 6,194 | 62.9% |
| WARN | 1,646 | 16.7% |
| DEBUG | 1,526 | 15.5% |
| ERROR | 453 | 4.6% |
| CRITICAL | 28 | 0.3% |

## Errors over time (5-minute buckets)

```text
▁▁▁▁▁▁▁▁▁▁▁▁▁▂▁▂▁▂▁▂▃▂▁▁▁▁▁▁▁▁▂▁▁▁▁▁▄▁▁▁▁▁▁▁▁▁▁▁▁▁▁▃▂▁▁▁▁▁▁▆█▂▁▁▁▁▁▁▁▂▁▁
2026-11-11 09:00 UTC                                      2026-11-11 14:59 UTC
```

## Spikes

### Spike 1: 2026-11-11 12:00 to 2026-11-11 12:01 UTC (2 min)

Peak **12** errors/min against a normal 1.28/min; 22 errors in total. Main causes:

- 21 × NullPointerException in OrderService\.process\(order\_id=\<UUID\>\)
- 1 × Order \<UUID\> stuck in state PENDING for \<NUM\>s

### Spike 2: 2026-11-11 13:16 to 2026-11-11 13:16 UTC (1 min)

Peak **11** errors/min against a normal 0.79/min; 11 errors in total. Main causes:

- 9 × Database connection timeout after \<NUM\>ms \(host=db\-\<NUM\>\.internal, pool=primary\)
- 1 × Order \<UUID\> stuck in state PENDING for \<NUM\>s
- 1 × Upstream inventory\-service returned HTTP \<NUM\> for GET /v\<NUM\>/stock/\<NUM\>

### Spike 3: 2026-11-11 13:58 to 2026-11-11 14:02 UTC (5 min)

Peak **18** errors/min against a normal 1.44/min; 84 errors in total. Main causes:

- 80 × Database connection timeout after \<NUM\>ms \(host=db\-\<NUM\>\.internal, pool=primary\)
- 2 × NullPointerException in OrderService\.process\(order\_id=\<UUID\>\)
- 1 × Order \<UUID\> stuck in state PENDING for \<NUM\>s

## Top 10 error groups

| # | Count | Error (variable parts masked) | Services | First seen | Last seen |
|---:|---:|---|---|---|---|
| 1 | 136 | Database connection timeout after \<NUM\>ms \(host=db\-\<NUM\>\.internal, pool=primary\) | inventory\-service, order\-service, payment\-service | 09:03:53 | 14:59:41 |
| 2 | 61 | NullPointerException in OrderService\.process\(order\_id=\<UUID\>\) | order\-service | 09:04:16 | 14:47:01 |
| 3 | 42 | Rate limit exceeded for client \<IP\> \(\<NUM\> req/min\) | api\-gateway | 09:10:07 | 14:59:55 |
| 4 | 41 | Payment declined for user \<NUM\>: card expired \(amount=\<NUM\> EUR\) | payment\-service | 09:03:50 | 14:49:33 |
| 5 | 41 | Upstream inventory\-service returned HTTP \<NUM\> for GET /v\<NUM\>/stock/\<NUM\> | api\-gateway, order\-service | 09:12:13 | 14:41:32 |
| 6 | 33 | Email to \<EMAIL\> bounced: mailbox full | notification\-service | 09:00:29 | 14:26:47 |
| 7 | 29 | Invalid JWT for session \<HEX\>: signature mismatch | auth\-service | 09:07:19 | 14:24:34 |
| 8 | 27 | Order \<UUID\> stuck in state PENDING for \<NUM\>s | order\-service | 09:02:54 | 14:59:56 |
| 9 | 18 | Consumer group billing lagging by \<NUM\> messages on topic orders\.v\<NUM\> partition \<NUM\> | inventory\-service | 09:11:43 | 14:49:04 |
| 10 | 17 | Worker \<NUM\> killed: out of memory \(rss=\<NUM\>MB\) | order\-service, inventory\-service | 09:30:05 | 14:35:17 |

## Malformed lines

| Reason | Lines |
|---|---:|
| missing\_service | 39 |
| unknown\_level | 31 |
| no\_timestamp | 29 |
| binary\_garbage | 25 |
| invalid\_timestamp | 23 |
| missing\_level | 6 |

First examples (control characters shown as \xNN):

| Line | Reason | Raw text |
|---:|---|---|
| 70 | invalid\_timestamp | 2026\-13\-11T09:02:56\.552Z INFO \[order\-service\] Order 3338ec24\-9a6a\-46a0\-8a8f\-fd65aed80127 created \(i… |
| 152 | no\_timestamp | 11/11/2026 09:06:03 INFO \[auth\-service\] POST /v1/cart 201 174ms |
| 156 | missing\_service | 2026\-11\-11T09:06:32\.539Z WARN order\-service Slow query 2128ms on table orders |
| 169 | unknown\_level | 2026\-11\-11T09:07:15\.075Z INF0 \[auth\-service\] User 13008 logged in from 142\.150\.82\.196 |
| 170 | missing\_service | 2026\-11\-11T09:07:16\.988Z INFO \[i |
| 197 | missing\_service | 2026\-11\-11T09:08:18\.297Z DEBUG api\-gateway Cache lookup key=user:17589:profile hit=true |
| 228 | invalid\_timestamp | 2026\-13\-11T09:09:47\.870Z INFO \[inventory\-service\] User 83249 logged in from 241\.226\.8\.59 |
| 311 | binary\_garbage | ْ��̕�Ä�鴇������Պ� |
| 359 | missing\_service | 2026\-11\-11T09:14:45\.796Z INFO notification\-service POST /v1/cart 201 44ms |
| 382 | unknown\_level | 2026\-11\-11T09:15:47\.731Z INF0 \[notification\-service\] User 61494 logged in from 234\.17\.61\.66 |


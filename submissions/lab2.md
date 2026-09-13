# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

## Цель и границы работы

В работе выполнено два уровня threat modeling для OWASP Juice Shop:

1. Архитектурная модель из `labs/lab2/threagile-model.yaml`: браузер, reverse proxy, приложение, постоянное хранилище и внешний WebHook.
2. Меньшая feature-level модель из `labs/lab2/threagile-model-auth.yaml`: только аутентификация и доступ к административному действию.

Результаты ниже получены заново из YAML-моделей Threagile `0.9.1`. В отчёте используются только артефакты Lab 2; наблюдения, команды запуска и результаты из Lab 1 сюда не перенесены.

## Среда и воспроизводимость

- Инструмент: `threagile/threagile:0.9.1` (внутри контейнера Threagile сообщает версию модели `1.0.0`).
- Входные модели: baseline `threagile-model.yaml`, защищённый вариант `threagile-model-secure.yaml`, модель login flow `threagile-model-auth.yaml`.
- Каталоги отчётов: `labs/lab2/output`, `labs/lab2/output-secure` и `labs/lab2/output-auth`.
- Сообщение `Fontconfig error: No writable cache directories` выводилось контейнером, но не помешало генерации всех ожидаемых артефактов: `risks.json`, `stats.json`, `risks.xlsx`, `report.pdf` и диаграмм.

Команды, которыми можно повторить расчёт из корня репозитория в PowerShell:

```powershell
New-Item -ItemType Directory -Force labs/lab2/output, labs/lab2/output-secure, labs/lab2/output-auth

docker run --rm -v "${PWD}/labs/lab2:/app/work" threagile/threagile:0.9.1 `
  -model /app/work/threagile-model.yaml -output /app/work/output

docker run --rm -v "${PWD}/labs/lab2:/app/work" threagile/threagile:0.9.1 `
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure

docker run --rm -v "${PWD}/labs/lab2:/app/work" threagile/threagile:0.9.1 `
  -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth
```

Для подсчётов использовались `risks.json`, а не визуальная оценка PDF. Серьёзности намеренно перечислены в порядке Threagile (`critical → high → elevated → medium → low`), а не в алфавитном.

## Task 1 — Baseline threat model

### 1.1 Сводка рисков

Baseline-расчёт нашёл **23** риска.

| Severity | Количество |
|---|---:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Итого** | **23** |

Это не означает, что четыре elevated-риска одинаковы по реальной цене атаки: severity — приоритизация правила Threagile, а окончательная оценка должна учитывать конкретные компенсирующие контроли и способ эксплуатации.

### 1.2 Пять наиболее приоритетных строк

Threagile не задаёт стабильный порядок записей с одинаковой severity. Поэтому для воспроизводимого top-5 применено явное tie-break правило: сначала порядок severity (`critical → high → elevated → medium → low`), затем `category`, затем `most_relevant_technical_asset`. HTML-теги из поля `title` убраны для читаемости.

| № | Severity | Rule ID | Основной актив | STRIDE | Почему это соответствует STRIDE |
|---:|---|---|---|---|---|
| 1 | Elevated | `cross-site-scripting` | `juice-shop` | **T — Tampering** | XSS позволяет внедрить и исполнить изменённый клиентский код в контексте приложения, меняя то, что видит и отправляет пользователь. |
| 2 | Elevated | `missing-authentication` | `juice-shop` | **S — Spoofing** | Для `Reverse Proxy → Juice Shop` задано `authentication: none`; приложение не может криптографически отличить доверенный proxy от подменившего его клиента/сервиса. |
| 3 | Elevated | `unencrypted-communication` | `reverse-proxy` | **I — Information Disclosure** | Связь `To App` от proxy к приложению использует HTTP и переносит session/token data, раскрывая их тому, кто может наблюдать внутренний сегмент. |
| 4 | Elevated | `unencrypted-communication` | `user-browser` | **I — Information Disclosure** | Связь `Direct to App (no proxy)` передаёт session ID/аутентификационные данные по HTTP, поэтому наблюдатель сети может их прочитать и украсть сессию. |
| 5 | Medium | `container-baseimage-backdooring` | `juice-shop` | **T — Tampering** | Компрометированный base image позволяет незаметно изменить код или зависимости контейнера ещё до запуска приложения. |

### 1.3 Переход через trust boundary

Особенно важна стрелка **`User Browser → Juice Shop Application`** с именем `Direct to App (no proxy)`. Она пересекает границу **Internet** и вложенные в неё границы **Host / Container Network**, то есть переносит session data из недоверенной сети непосредственно к приложению. В baseline это HTTP, поэтому атакующему достаточно занять позицию наблюдателя или активного посредника на пути трафика, чтобы перехватить/изменить данные до того, как приложение сможет их обработать. Это объясняет одновременно elevated `unencrypted-communication` и практический приоритет устранения прямого открытого канала.

### 1.4 Что именно охватывает baseline

Архитектурная модель фиксирует пять data assets: учётные записи, заказы, каталог, токены/сессии и логи. В ней есть пять technical assets: пользовательский браузер, reverse proxy, Juice Shop, persistent storage и внешний WebHook endpoint. Это сознательно архитектурный срез: он хорошо показывает доверительные границы, каналы и места хранения, но не раскрывает порядок шагов входа пользователя.

## Task 2 — Secure variant and diff

Защищённая версия находится в `labs/lab2/threagile-model-secure.yaml`. Она сохраняет те же основные активы и потоки baseline-модели, но меняет только свойства защиты, необходимые для проверки риска:

1. `User Browser → Juice Shop Application`, `Direct to App (no proxy)`: `protocol: http` → `protocol: https`.
2. `Reverse Proxy → Juice Shop Application`, `To App`: `protocol: http` → `protocol: https`.
3. Та же связь proxy → application: `authentication: none` → `authentication: client-certificate`; также указан `authorization: technical-user`.
4. `Juice Shop Application`: `encryption: none` → `data-with-symmetric-shared-key`.
5. `Persistent Storage`: `encryption: none` → `data-with-symmetric-shared-key`.

`client-certificate` здесь моделирует mTLS/проверку клиентского сертификата: TLS защищает конфиденциальность канала, а сертификат дополнительно подтверждает, что запрос к приложению направляет именно разрешённый proxy. Сам YAML является моделью целевого контроля; для production понадобятся сертификаты, ротация ключей, корректная настройка reverse proxy и проверка этого контроля в развёртывании.

### 2.1 Изменение количества рисков

| Severity | Baseline | Secure | Delta (Secure − Baseline) |
|---|---:|---:|---:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | −3 |
| Medium | 14 | 12 | −2 |
| Low | 5 | 5 | 0 |
| **Итого** | **23** | **18** | **−5** |

Итог снизился на 5 рисков, то есть примерно на **21.7%**. Новых категорий в защищённом запуске не появилось.

### 2.2 Исчезнувшие rule IDs и причина

Команда сравнения уникальных `category` показала `gone:`:

| Исчезнувший rule ID | Поле(я), изменённые в secure model | Почему правило больше не срабатывает |
|---|---|---|
| `unencrypted-communication` | Оба входящих в приложение канала: `http` → `https` | Threagile больше не видит открытый протокол на связи, где передаются tokens/sessions. |
| `missing-authentication` | `Reverse Proxy → To App`: `authentication: none` → `client-certificate` | Канал теперь содержит явно объявленный механизм service-to-service authentication. |
| `unencrypted-asset` | `juice-shop` и `persistent-storage`: `encryption: none` → `data-with-symmetric-shared-key` | Оба актива, ранее отмеченные как незашифрованные, получили тип encryption at rest. |

### 2.3 Риски, которые остались

| Оставшийся rule ID | Почему изменения его не закрывают | Что нужно сделать вне описания YAML |
|---|---|---|
| `cross-site-scripting` | TLS, mTLS и encryption at rest не меняют обработку пользовательского ввода и рендеринг страниц в приложении. | Устранить уязвимый sink в коде, использовать контекстное output encoding/санитизацию, включить строгий CSP и добавить тесты на stored/reflected XSS. |
| `server-side-request-forgery` | Outbound-связь `Juice Shop → Webhook Endpoint` осталась: шифрование защищает канал, но не делает допустимым адрес назначения. | Валидировать/allowlist-ить URL и DNS-результаты, блокировать private/link-local адреса и ограничить egress на сетевом уровне. |

### 2.4 Что осталось после hardening

После изменения транспорта и хранения данных в модели остаются главным образом риски поведения приложения и операционные/архитектурные пробелы: XSS, CSRF, SSRF, отсутствие vault/identity store, hardening и защита цепочки поставки container image. Шифрование не исправляет небезопасную бизнес-логику, необработанный ввод и избыточные привилегии. Для закрытия этих проблем потребуются изменения кода, тестов, сетевой политики, secret management и CI/CD-процесса. Например, **XSS нельзя закрыть одной YAML-правкой**: модель может зафиксировать контроль, но исправление требует изменить обработку данных в приложении и подтвердить результат тестированием.

## Bonus — authentication flow model

### 3.1 Отдельная feature-level модель

`labs/lab2/threagile-model-auth.yaml` создана от stub-модели Threagile как отдельная минимальная модель, а не путём удаления частей baseline. Её объектная структура:

| Требование | Реализация в модели |
|---|---|
| Не менее 5 technical assets | `user-browser`, `login-endpoint`, `token-service`, `credential-store`, `admin-endpoint` — **5**. |
| Не менее 5 communication links | `Submit Credentials`, `Request Admin Action`, `Check Password Hash`, `Request JWT`, `Validate JWT and Role` — **5**. |
| Не менее 4 data assets | `login-credentials`, `jwt-access-token`, `jwt-signing-key`, `account-roles`, `auth-audit-log` — **5**. |
| JWT signing key отдельным data asset | `JWT Signing Key` / ID `jwt-signing-key`; он обрабатывается и хранится в `token-service`. |
| Authentication и authorization у каждой связи | Все пять links содержат оба поля. Внешние запросы используют `credentials`/`token` и `enduser-identity-propagation`; внутренние — `client-certificate` и `technical-user`. |
| Защита admin endpoint | Связь `Admin Endpoint → Token Service`, `Validate JWT and Role`, проверяет подпись JWT, expiry, audience и administrator role до выполнения административного действия. |

Модель также использует HTTPS для browser-facing и service-to-service HTTP-связей, зашифрованный JDBC к credential store и encryption at rest для token service/credential store. Это не «заявление о том, что реализация уже безопасна», а явно сформулированное целевое свойство анализируемого потока.

### 3.2 Сводка рисков login flow

Отдельный запуск `output-auth/risks.json` нашёл **22** риска.

| Severity | Количество |
|---|---:|
| Critical | 0 |
| High | 1 |
| Elevated | 7 |
| Medium | 13 |
| Low | 1 |
| **Итого** | **22** |

### 3.3 Риски, которые показала feature-level модель

Следующие rule IDs не присутствуют в baseline architecture model и становятся видимыми именно после разбиения login path на отдельные активы и вызовы.

| Rule ID | STRIDE | Что выявлено | Одно конкретное направление mitigation |
|---|---|---|---|
| `sql-nosql-injection` | **T — Tampering** | `Login Endpoint → Credential Store` передаёт данные, происходящие из credentials, к database; инъекция может изменить смысл запроса и обойти проверку учётной записи. | Использовать параметризованные запросы/безопасный ORM, строго валидировать вход и выдать DB-account только минимальные read-права. |
| `unguarded-access-from-internet` | **E — Elevation of Privilege** | Административный endpoint доступен от browser через Internet boundary; одного bearer token недостаточно как сетевого барьера для особенно привилегированной функции. | Вынести admin route за VPN/allowlist/API gateway, добавить MFA и сохранить server-side role-check. |
| `missing-identity-provider-isolation` | **E — Elevation of Privilege** | Credential Store находится в одном application segment с менее защищёнными компонентами, поэтому компрометация соседнего процесса может стать ступенью к identity data. | Разделить identity store в отдельный сегмент/namespace и применить deny-by-default network policy только для login service. |

### 3.4 Вывод по уровню детализации

Архитектурная модель хорошо отвечает на вопрос «какие системы и границы надо защищать», но объединяет всю аутентификацию в один application asset. Feature-level модель показывает конкретные точки, где credentials попадают в database, где рождается JWT, где применяется signing key и где проверяется admin role. Поэтому она обнаруживает риск инъекции и отдельные проблемы изоляции/доступности admin endpoint, которые невозможно корректно локализовать в более крупной архитектурной модели.

## Артефакты для PR

- `submissions/lab2.md` — этот отчёт.
- `labs/lab2/threagile-model-secure.yaml` — защищённая архитектурная модель.
- `labs/lab2/threagile-model-auth.yaml` — отдельная модель login/admin flow (bonus).

Каталоги `labs/lab2/output*` намеренно не добавляются в Git: они воспроизводимы из YAML и уже игнорируются репозиторием.

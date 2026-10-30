# Руководство по развёртыванию Mega-Analyzer в Docker

[English](DOCKER_DEPLOYMENT.md)

Это руководство содержит подробные инструкции по развёртыванию Mega-Analyzer с помощью Docker и Docker Compose.

## Требования

- Docker 20.10+
- Docker Compose 2.0+
- Минимум 8 ГБ ОЗУ
- 50 ГБ свободного места на диске
- Ядро Linux с поддержкой KVM (для Android-эмулятора)

## Быстрый старт

Единственный путь, гарантированно работающий из коробки, — собрать и запустить
один образ `analyzer`: поставляемый `Dockerfile` собирает один статический
чисто-Go бинарник с `CGO_ENABLED=0`, без зависимостей от базы данных, кеша или
эмулятора (см. [BUILD.ru.md](BUILD.ru.md)). Всё, что описано ниже в разделе
«Опциональные / иллюстративные дополнительные сервисы», — это пример обвязки
для твоей собственной оркестрации, а не поддерживаемый или обязательный путь
развёртывания.

### 1. Собрать Docker-образ

```bash
# Собрать основной образ Mega-Analyzer
docker build -t mega-analyzer:latest .

# Проверить сборку
docker images | grep mega-analyzer
```

### 2. Запустить анализатор

```bash
# Выполнить один анализ и выйти
docker run --rm \
  -v "$(pwd)/workspace:/home/analyzer/workspace:ro" \
  -v "$(pwd)/reports:/home/analyzer/reports:rw" \
  mega-analyzer:latest \
  -t /home/analyzer/workspace/app.apk --ml-patch --crackpoint-analysis -o /home/analyzer/reports
```

Или через `docker-compose.yml`:

```bash
# При первом запуске скопируй пример и задай MEGA_ANALYZER_API_TOKEN в .env.
# Случайный токен можно сгенерировать командой: openssl rand -hex 32
cp .env.example .env

# Поднимает только основной сервис анализатора — дополнительные сайдкары ниже
# закрыты профилями Compose и НЕ стартуют при голом `up`.
docker-compose up -d

# Проверить статус / логи
docker-compose ps
docker-compose logs -f analyzer

# Зайти в контейнер и запустить анализатор вручную
docker-compose exec analyzer bash
analyzer -t /home/analyzer/workspace/app.apk --ml-patch --crackpoint-analysis -o /home/analyzer/reports
```

API доступен по адресу `http://127.0.0.1:5000`. Передавай токен из `.env`
в заголовке `Authorization: Bearer <token>` или `X-Mega-Analyzer-Token`:

```bash
curl -H 'Authorization: Bearer <токен из .env>' http://127.0.0.1:5000/api/v1/status
```

Внутри контейнера API слушает `0.0.0.0`, а Docker публикует порт только на
loopback-интерфейсе хоста. Без токена Compose откажется запускать сервис.
Отчёты и загруженные артефакты сохраняются в `./reports/api`; локальные
файлы для сканирования должны находиться внутри `./workspace`.

## Конфигурация

### Переменные окружения

Бинарник анализатора читает свою конфигурацию из переменных окружения с
префиксом `ANALYZER_*` (полный и краткий справочники — в
[FlagiFiles.md](../FlagiFiles.md) и [USAGE.ru.md](USAGE.ru.md)) — например:

```yaml
environment:
  - ANALYZER_OUTPUT_DIR=/home/analyzer/reports
  - ANALYZER_WORKERS=4
  - ANALYZER_LOG_LEVEL=info
  - ANALYZER_PROFILE=deep
```

REST-сервер использует отдельные настройки `MEGA_ANALYZER_*`, заданные в Compose:

| Переменная | Значение в контейнере / назначение |
| --- | --- |
| `MEGA_ANALYZER_API_BIND` | `0.0.0.0` для проброса порта Docker |
| `MEGA_ANALYZER_API_TOKEN` | Обязательный секретный токен из `.env` |
| `MEGA_ANALYZER_SCAN_ROOT` | `/home/analyzer/workspace`, разрешённые входные файлы |
| `MEGA_ANALYZER_JOB_ROOT` | `/home/analyzer/reports/api`, задания и артефакты |
| `MEGA_ANALYZER_SCAN_CONCURRENCY` | `4`, число одновременных сканов API |

ML/MITM/песочница управляются флагами CLI (`--ml-patch`, `-android-sandbox`
и т.д.), а не переключателями окружения.

### Монтирование томов

- `./workspace`: входные файлы APK/DEX
- `./reports`: выходные отчёты анализа
- `./configs`: файлы конфигурации

## Опциональные / иллюстративные дополнительные сервисы

`docker-compose.yml` также определяет сайдкар mitmproxy, контейнер с
Android-эмулятором, PostgreSQL и Redis — каждый закрыт собственным
[профилем](https://docs.docker.com/compose/how-tos/profiles/) Compose
(`mitm`, `android`, `postgres`, `redis`), поэтому обычный `docker-compose up -d`
их никогда не запускает. **Ни один из них не используется бинарником
анализатора** — у него нет клиента базы данных или кеша, и он не читает
переключатели MITM/песочницы из окружения. Они оставлены как пример обвязки для
тех, кто хочет построить свою оркестрацию вокруг Mega-Analyzer, а не как
поддерживаемый путь.

Чтобы включить один или несколько, добавь нужные пароли в существующий `.env`
(см. [`.env.example`](../.env.example)) и передай профиль(и) явно.
PostgreSQL и Redis откажутся запускаться с пустым паролем; для основного
анализатора эти пароли не нужны.

```bash
# Заполни POSTGRES_PASSWORD / REDIS_PASSWORD в .env, сохранив токен API.

docker-compose --profile postgres up -d   # + PostgreSQL
docker-compose --profile redis up -d      # + Redis
docker-compose --profile mitm up -d       # + mitmproxy
docker-compose --profile android up -d    # + Android-эмулятор (только хост Linux/KVM)
```

### MITM-прокси (опционально, с анализатором не связан)

```bash
# Доступ к веб-интерфейсу mitmproxy
# Открой http://localhost:8081

# Настроить прокси в Android-эмуляторе
adb shell settings put global http_proxy 127.0.0.1:8080
```

### Android-эмулятор (опционально, с анализатором не связан)

```bash
# Подключиться к эмулятору
docker-compose exec analyzer adb connect android-emulator:5555

# Список подключённых устройств
docker-compose exec analyzer adb devices

# Установить тестовый APK
docker-compose exec analyzer adb install /home/analyzer/workspace/test.apk
```

### PostgreSQL (опционально, с анализатором не связан)

Анализатор сам не читает из этой базы и не пишет в неё — она предоставлена
только как отправная точка, если ты хочешь сохранять результаты самостоятельно.

```bash
# Подключиться к базе
docker-compose exec postgres psql -U analyzer -d mega_analyzer

# Пример запроса
SELECT * FROM analysis_results ORDER BY created_at DESC LIMIT 10;
```

### Redis (опционально, с анализатором не связан)

Анализатор сам не использует Redis для кеширования или сессий — он предоставлен
только как отправная точка для твоего собственного тулинга.

```bash
# Подключиться к Redis
docker-compose exec redis redis-cli

# Посмотреть статистику кеша
DBSIZE
INFO stats
```

## Тюнинг производительности

### Лимиты ресурсов

Настрой лимиты ресурсов в `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '8'        # Увеличь для более быстрого анализа
      memory: 16G      # Увеличь для больших APK
    reservations:
      cpus: '4'
      memory: 8G
```

### Рабочие потоки

Настрой количество воркеров для параллельного анализа:

```bash
docker-compose exec analyzer analyzer --workers 8
```

### Ускорение на GPU (опционально)

Чтобы включить GPU-ускорение для ML-моделей:

```yaml
services:
  analyzer:
    runtime: nvidia
    environment:
      - CUDA_VISIBLE_DEVICES=0
```

## Устранение неполадок

### Контейнер не запускается

```bash
# Посмотреть логи
docker-compose logs analyzer

# Проверить образ
docker inspect mega-analyzer:latest

# Пересобрать образ
docker-compose build --no-cache
```

### Нехватка памяти

```bash
# Увеличить лимит памяти Docker
# Отредактируй настройки Docker Desktop либо выполни:
docker update --memory 16g mega-analyzer
```

### Проблемы с сетью

```bash
# Проверить сетевую связность
docker-compose exec analyzer ping 8.8.8.8

# Проверить MITM-прокси
docker-compose exec analyzer curl -x http://mitm-proxy:8080 https://example.com
```

### Android-эмулятор не подключается

```bash
# Проверить статус эмулятора
docker-compose exec analyzer adb devices

# Перезапустить эмулятор
docker-compose restart android-emulator

# Посмотреть логи
docker-compose logs android-emulator
```

## Очистка

```bash
# Остановить все сервисы
docker-compose down

# Удалить тома
docker-compose down -v

# Удалить образы
docker rmi mega-analyzer:latest

# Подчистить неиспользуемые ресурсы
docker system prune -a
```

## Продакшен-развёртывание

### Соображения безопасности

1. **Используй приватный реестр**: пуш образов в приватный Docker-реестр
2. **Подписывай образы**: Docker Content Trust для подписи образов
3. **Изоляция сети**: запускай контейнеры в изолированной сети
4. **Управление секретами**: используй Docker secrets для чувствительных данных
5. **Лимиты ресурсов**: задавай адекватные лимиты CPU и памяти

### Развёртывание в Kubernetes

Пример манифеста Kubernetes Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mega-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mega-analyzer
  template:
    metadata:
      labels:
        app: mega-analyzer
    spec:
      containers:
      - name: analyzer
        image: mega-analyzer:latest
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        volumeMounts:
        - name: workspace
          mountPath: /home/analyzer/workspace
        - name: reports
          mountPath: /home/analyzer/reports
      volumes:
      - name: workspace
        persistentVolumeClaim:
          claimName: analyzer-workspace
      - name: reports
        persistentVolumeClaim:
          claimName: analyzer-reports
```

## Интеграция с CI/CD

### Пример GitHub Actions

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Build Docker image
        run: docker build -t mega-analyzer:ci .

      - name: Run analysis
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/home/analyzer/workspace \
            -v ${{ github.workspace }}/reports:/home/analyzer/reports \
            mega-analyzer:ci \
            analyzer -t /home/analyzer/workspace/app.apk -o /home/analyzer/reports

      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: analysis-reports
          path: reports/
```

### Пример GitLab CI

```yaml
analyze:
  image: mega-analyzer:latest
  script:
    - analyzer -t $CI_PROJECT_DIR/app.apk -o $CI_PROJECT_DIR/reports
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
```

## Мониторинг

### Health-чеки

Docker Compose включает health-чеки для всех сервисов:

```bash
# Проверить здоровье сервисов
docker-compose ps

# Посмотреть логи health-чеков
docker inspect mega-analyzer | grep -A 20 "Health"
```

### Логирование

Конфигурация централизованного логирования:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
```

### Метрики

Мониторинг метрик контейнера:

```bash
# Статистика в реальном времени
docker stats mega-analyzer

# Исторические данные
docker stats --no-stream mega-analyzer
```

## Поддержка и документация

- [Официальная документация Docker](https://docs.docker.com/)
- [Справочник Docker Compose](https://docs.docker.com/compose/compose-file/)
- [Mega-Analyzer README](../README.ru.md)
- [Архитектура](ARCHITECTURE.ru.md)

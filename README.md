# mwg

Управление двумя туннелями WireGuard / AmneziaWG: корпоративным и интернет-туннелем
(через который идёт default-маршрут `0.0.0.0/0`).

Работает на Linux, macOS и Windows.

## Команды

| Команда | Описание |
| --- | --- |
| `mwg up` | запуск туннелей: сначала corp, затем internet |
| `mwg down` | остановка туннелей в обратном порядке |
| `mwg conf -c <path>` | добавить конфиг корпоративного туннеля |
| `mwg conf -e <path>` | добавить конфиг интернет-туннеля (`0.0.0.0/0`) |
| `mwg conf` | показать сохранённые конфиги |
| `mwg show tun` | показать интерфейсы wg/awg |
| `mwg show route` | показать маршруты только через wg/awg интерфейсы |
| `mwg check` | проверить наличие wg/awg утилит |
| `mwg version` | версия |

## Что делает приложение

1. **Определяет тип туннеля** по содержимому конфига:
   - ключи `Jc`, `Jmin`, `Jmax`, `S1..S4`, `H1..H4`, `I1..I5`, `J1..J3`, `Itime`
     в секции `[Interface]` означают AmneziaWG;
   - иначе — WireGuard.
2. **Проверяет утилиты**:
   - Linux/macOS: `wg-quick` + `wg` либо `awg-quick` + `awg`;
   - Windows: `wireguard.exe` + `wg.exe` либо `amneziawg.exe` + `awg.exe`.
   Учитывается `PATH` и стандартные каталоги установки
   (`C:\Program Files\WireGuard`, `C:\Program Files\AmneziaWG`,
   `/opt/homebrew/bin`, `/usr/local/bin` и т.п.).
3. **Хранит копии конфигов** в каталоге состояния и запускает туннели:
   - Linux/macOS: `wg-quick up <config>` / `awg-quick up <config>`;
   - Windows: `wireguard.exe /installtunnelservice <config>`.
4. **Проверяет default-маршрут**: `AllowedIPs = 0.0.0.0/0` (или `::/0`, или пара
   `0.0.0.0/1` + `128.0.0.0/1`) разрешён только интернет-конфигу (`-e`).
   Корпоративный конфиг с `0.0.0.0/0` отклоняется. Проверка повторяется
   при `mwg up` и при `mwg show route` (по реальной таблице маршрутизации).
5. **Показывает маршруты** только через интерфейсы `wg*`, `awg*`, `mwg*`.

## Каталог состояния

| ОС | Путь |
| --- | --- |
| Linux | `~/.config/mwg` |
| macOS | `~/Library/Application Support/mwg` |
| Windows | `%AppData%\mwg` |

В каталоге лежат `state.json` и копии конфигов `mwgcorp.conf` / `mwginet.conf`.

## Сборка

```sh
go build -o mwg .
```

Для управления туннелями нужны права root (Linux/macOS: `sudo mwg up`)
или администратора (Windows).

## Тесты

```sh
go test ./...
```

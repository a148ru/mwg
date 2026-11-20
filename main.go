package main

import (
	"fmt"
	"os"
	"runtime"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	switch args[0] {
	case "up":
		return cmdUp(args[1:])
	case "down":
		return cmdDown(args[1:])
	case "conf":
		return cmdConf(args[1:])
	case "show":
		return cmdShow(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("mwg %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", args[0])
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Print(`mwg — управление двумя туннелями WireGuard / AmneziaWG

Использование:
  mwg up                    запустить туннели (corp, затем internet)
  mwg down                  остановить туннели (в обратном порядке)
  mwg conf -c <path>        добавить конфиг корпоративного туннеля
  mwg conf -e <path>        добавить конфиг интернет-туннеля (0.0.0.0/0)
  mwg conf                  показать сохранённые конфиги
  mwg show tun              показать интерфейсы wg/awg
  mwg show route            показать маршруты через wg/awg туннели
  mwg check                 проверить наличие wg/awg утилит
  mwg version               версия

Правила:
  * тип туннеля (WireGuard / AmneziaWG) определяется по содержимому конфига;
  * AllowedIPs 0.0.0.0/0 разрешён только интернет-конфигу (mwg conf -e);
  * корпоративный конфиг не должен содержать 0.0.0.0/0 (кроме Table = off);
  * запуск и остановка требуют прав root (Linux/macOS: sudo) или
    администратора (Windows).

Каталог состояния:
  Linux   ~/.config/mwg
  macOS   ~/Library/Application Support/mwg
  Windows %AppData%\mwg
`)
}

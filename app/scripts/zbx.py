"""Значения для Zabbix agent (UserParameter) из последнего замера мониторинга.

  zbx.py <current.json> get <ключ>          -> число или текст
  zbx.py <current.json> discovery <список>  -> JSON для низкоуровневого обнаружения (LLD)

Ключ age — сколько секунд назад был замер (если сборщик встал — растёт).
Только стандартная библиотека: запускается агентом на каждый запрос.
"""
import json
import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: zbx.py <current.json> get|discovery <name>", file=sys.stderr)
        return 2
    path, action, name = argv[1], argv[2], argv[3]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"no monitoring data: {e}", file=sys.stderr)
        return 1
    if action == "discovery":
        print(json.dumps(data.get("discovery", {}).get(name, []), ensure_ascii=False))
        return 0
    if name == "age":
        print(int(time.time() - float(data.get("time") or 0)))
        return 0
    value = data.get("values", {}).get(name)
    if value is None:
        print(f"no value for {name}", file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

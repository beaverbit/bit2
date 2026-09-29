# bit2 - makefile do bagulho
# so o basico que funciona

PY      ?= python3
BIN     := bit2
TARGET  ?= 127.0.0.1
NET     ?= 192.168.0.0/24
PORTS   ?= 1-1024
THREADS ?= 200

.PHONY: help run top scan live full net net-live install uninstall lint fmt clean test

help:
	@echo "bit2 - targets:"
	@echo "  make run TARGET=host          -> top 100, ordenado (default)"
	@echo "  make live TARGET=host         -> top 100, tempo real"
	@echo "  make scan TARGET=host PORTS=x -> portas customizadas"
	@echo "  make full TARGET=host         -> 1-1024 com banner grab"
	@echo "  make net NET=192.168.0.0/24   -> varre rede toda"
	@echo "  make net-live NET=x.x.x.x/24  -> varre rede, tempo real"
	@echo "  make install                  -> joga o bit2 no /usr/local/bin"
	@echo "  make uninstall                -> tira"
	@echo "  make lint                     -> checa sintaxe"
	@echo "  make clean                    -> limpa lixo"

run:
	@$(PY) $(BIN).py --top -sV $(TARGET)

top: run

live:
	@$(PY) $(BIN).py --top -sV --live $(TARGET)

scan:
	@$(PY) $(BIN).py -p $(PORTS) -t $(THREADS) -sV $(TARGET)

full:
	@$(PY) $(BIN).py -p 1-1024 -t $(THREADS) -sV $(TARGET)

net:
	@$(PY) $(BIN).py --top -sV -T 0.8 $(NET)

net-live:
	@$(PY) $(BIN).py --top -sV -T 0.8 --live $(NET)

install:
	@install -m 0755 $(BIN).py /usr/local/bin/$(BIN)
	@install -m 0755 $(BIN).sh /usr/local/bin/$(BIN).sh
	@echo "instalado em /usr/local/bin/$(BIN)"

uninstall:
	@rm -f /usr/local/bin/$(BIN) /usr/local/bin/$(BIN).sh
	@echo "removido"

lint:
	@$(PY) -m py_compile $(BIN).py
	@bash -n $(BIN).sh
	@echo "ok"

fmt:
	@command -v black >/dev/null 2>&1 && black $(BIN).py || echo "black nao instalado, pulando"

test:
	@bash -n $(BIN).sh
	@$(PY) -m py_compile $(BIN).py
	@$(PY) $(BIN).py -p 22,80 --no-color --skip-discovery $(TARGET) || true

clean:
	@rm -rf __pycache__ *.pyc *.json
	@echo "limpo"

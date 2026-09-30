# bit2 - makefile do bagulho
# so o basico que funciona

PY      ?= python3
BIN     := bit2
TARGET  ?= 127.0.0.1
NET     ?= 192.168.0.0/24
PORTS   ?= 1-1024
THREADS ?= 200

.PHONY: help run top scan live full net net-live udp udp-top xml grep test test-cov lint fmt clean install uninstall ci

help:
	@echo "bit2 - targets:"
	@echo ""
	@echo "  -- scan --"
	@echo "  make run TARGET=host          -> top 100 TCP, ordenado"
	@echo "  make live TARGET=host         -> top 100 TCP, tempo real"
	@echo "  make scan TARGET=host PORTS=x -> portas customizadas"
	@echo "  make full TARGET=host         -> 1-1024 com banner grab"
	@echo "  make net NET=192.168.0.0/24   -> varre rede toda"
	@echo "  make net-live NET=x.x.x.x/24  -> varre rede, tempo real"
	@echo "  make udp TARGET=host          -> top UDP"
	@echo "  make udp-top TARGET=host      -> top UDP+TCP juntos"
	@echo "  make xml TARGET=host          -> saida XML"
	@echo "  make grep TARGET=host         -> saida grep-friendly"
	@echo ""
	@echo "  -- dev --"
	@echo "  make test                     -> roda pytest"
	@echo "  make test-cov                 -> pytest + cobertura"
	@echo "  make lint                     -> checa sintaxe py + sh"
	@echo "  make fmt                      -> roda black (se instalado)"
	@echo "  make ci                       -> lint + test (o que a CI roda)"
	@echo "  make clean                    -> limpa lixo"
	@echo ""
	@echo "  -- install --"
	@echo "  make install                  -> instala com pip (editable)"
	@echo "  make install-global           -> copia pra /usr/local/bin"
	@echo "  make uninstall                -> tira"

run:
	@$(PY) bit2.py --top -sV $(TARGET)

top: run

live:
	@$(PY) bit2.py --top -sV --live $(TARGET)

scan:
	@$(PY) bit2.py -p $(PORTS) -t $(THREADS) -sV $(TARGET)

full:
	@$(PY) bit2.py -p 1-1024 -t $(THREADS) -sV $(TARGET)

net:
	@$(PY) bit2.py --top -sV -T 0.8 $(NET)

net-live:
	@$(PY) bit2.py --top -sV -T 0.8 --live $(NET)

udp:
	@$(PY) bit2.py -sU --top-udp -sV $(TARGET)

udp-top:
	@$(PY) bit2.py -sU --also-tcp --top -sV $(TARGET)

xml:
	@$(PY) bit2.py --top -sV --output xml $(TARGET)

grep:
	@$(PY) bit2.py --top -sV --output grep $(TARGET)

test:
	@$(PY) -m pytest tests/ $(ARGS)

test-cov:
	@$(PY) -m pytest tests/ --cov=bit2 --cov-report=term-missing $(ARGS)

lint:
	@$(PY) -m py_compile bit2.py bit2/*.py
	@bash -n bit2.sh
	@echo "ok"

fmt:
	@command -v black >/dev/null 2>&1 && black bit2.py bit2/ tests/ || echo "black nao instalado, pulando"

ci: lint test

clean:
	@rm -rf __pycache__ bit2/__pycache__ tests/__pycache__ *.pyc bit2/*.pyc tests/*.pyc
	@rm -rf .pytest_cache .coverage coverage.xml htmlcov
	@rm -rf build dist *.egg-info
	@rm -f *.json
	@echo "limpo"

install:
	@$(PY) -m pip install -e ".[dev]"
	@echo "instalado em modo editable (comando: bit2)"

install-global:
	@install -m 0755 bit2.py /usr/local/bin/$(BIN)
	@install -m 0755 bit2.sh /usr/local/bin/$(BIN).sh
	@echo "instalado em /usr/local/bin/$(BIN)"

uninstall:
	@$(PY) -m pip uninstall -y bit2 || true
	@rm -f /usr/local/bin/$(BIN) /usr/local/bin/$(BIN).sh
	@echo "removido"

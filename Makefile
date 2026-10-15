# necropsy — the binary post-mortem kit
CC ?= cc
NIM ?= nim
SRC = src/necropsy.nim
OUT = bin/necropsy

.PHONY: build debug test e2e clean

build:
	mkdir -p bin
	$(NIM) c -d:release --mm:orc -o:$(OUT) $(SRC)

debug:
	mkdir -p bin
	$(NIM) c -d:debug --stacktrace:on -o:bin/necropsy_dbg $(SRC)

test: build e2e

e2e:
	bash test/e2e_local.sh

clean:
	rm -rf bin nimcache

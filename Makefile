# MOBS[ML-DSA] -- reference implementation in C
#
#   make            build libraries, tests, demo and benchmark for ML-DSA-44/65/87
#   make check      fast functional tests (insecure Ligero test parameters for the end-to-end run)
#   make check-full end-to-end test with production parameters (ML-DSA-44, ~1 min)
#   make bench      benchmark (production parameters)
#
# ML-DSA is the official reference implementation (pq-crystals/dilithium, FIPS 204
# version with context strings), compiled unmodified from third_party/.

CC      ?= cc
CFLAGS  ?= -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter
REF     := third_party/dilithium/ref
MODES   := 2 3 5
SRC     := src/field.c src/cs.c src/gadgets.c src/keccak_circuit.c src/mldsa_circuit.c src/ligero.c src/xof.c src/mobs.c
REFSRC  := sign packing polyvec poly ntt reduce rounding fips202 symmetric-shake randombytes
HDRS    := $(wildcard src/*.h)
LDLIBS  := -lm

all: $(foreach m,$(MODES),build/libmobs$(m).a build/test_mldsa_circuit$(m) build/test_mobs$(m) build/demo$(m) build/bench_mobs$(m)) \
     build/test_field build/test_xof build/test_keccak build/test_ligero

build:
	mkdir -p build

# ---- per-mode rules (ML-DSA-44 = mode 2, ML-DSA-65 = mode 3, ML-DSA-87 = mode 5) ----
define MODE_RULES
build/ref$(1)/%.o: $(REF)/%.c | build
	@mkdir -p build/ref$(1)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -c $$< -o $$@

build/obj$(1)/%.o: src/%.c $(HDRS) | build
	@mkdir -p build/obj$(1)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -c $$< -o $$@

build/libmobs$(1).a: $(patsubst src/%.c,build/obj$(1)/%.o,$(SRC)) $(foreach f,$(REFSRC),build/ref$(1)/$(f).o)
	ar rcs $$@ $$^

build/test_mldsa_circuit$(1): tests/test_mldsa_circuit.c build/libmobs$(1).a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -Isrc $$< build/libmobs$(1).a -o $$@ $(LDLIBS)

build/test_mobs$(1): tests/test_mobs.c build/libmobs$(1).a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -Isrc $$< build/libmobs$(1).a -o $$@ $(LDLIBS)

build/demo$(1): examples/demo.c build/libmobs$(1).a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -Isrc $$< build/libmobs$(1).a -o $$@ $(LDLIBS)

build/bench_mobs$(1): bench/bench_mobs.c build/libmobs$(1).a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(1) -I$(REF) -Isrc $$< build/libmobs$(1).a -o $$@ $(LDLIBS)
endef
$(foreach m,$(MODES),$(eval $(call MODE_RULES,$(m))))

# ---- mode-independent tests ----
build/test_field: tests/test_field.c src/field.c src/field.h | build
	$(CC) $(CFLAGS) tests/test_field.c src/field.c -o $@

build/test_xof: tests/test_xof.c build/libmobs2.a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -I$(REF) -Isrc $< build/libmobs2.a -o $@ $(LDLIBS)

build/test_keccak: tests/test_keccak.c build/libmobs2.a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -I$(REF) -Isrc $< build/libmobs2.a -o $@ $(LDLIBS)

build/test_ligero: tests/test_ligero.c build/libmobs2.a
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -I$(REF) -Isrc $< build/libmobs2.a -o $@ $(LDLIBS)

check: all
	./build/test_field
	./build/test_xof
	./build/test_keccak
	./build/test_ligero
	$(foreach m,$(MODES),./build/test_mldsa_circuit$(m) &&) true
	$(foreach m,$(MODES),./build/test_mobs$(m) --fast &&) true

check-full: build/test_mobs2
	./build/test_mobs2

bench: build/bench_mobs2
	./build/bench_mobs2

clean:
	rm -rf build

.PHONY: all check check-full bench clean

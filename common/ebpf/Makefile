BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_CFLAGS ?= -target bpfel -O2 -g0

SOURCE := native/shared_network.bpf.c
OBJECT := native/shared_network.bpf.o

.PHONY: generate check clean

generate:
	@temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) -Inative -I$(BPF_SYSTEM_INCLUDE) \
		-c "$(SOURCE)" -o "$$temporary"; \
	mv "$$temporary" "$(OBJECT)"

check:
	@temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) -Inative -I$(BPF_SYSTEM_INCLUDE) \
		-c "$(SOURCE)" -o "$$temporary"; \
	if ! cmp -s "$(OBJECT)" "$$temporary"; then \
		echo "$(OBJECT) is stale; run 'make generate' in this directory" >&2; \
		exit 1; \
	fi

clean:
	rm -f "$(OBJECT)"

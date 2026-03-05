TARGET := sentinel
BPF_OBJ := $(TARGET).bpf.o
SKEL := $(TARGET).skel.h

all: $(TARGET)

$(BPF_OBJ): $(TARGET).bpf.c shared.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(TARGET): $(TARGET).c $(SKEL)
	gcc -g -O2 $< -lbpf -lelf -lz -o $@

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL)

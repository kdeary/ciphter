BIN_DIR = bin
TARGET = $(BIN_DIR)/ciphter

all: $(TARGET)

$(TARGET): src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c src/english_detector.c src/utils.c src/ui.c
	mkdir -p $(BIN_DIR)
	gcc -g src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c src/english_detector.c src/utils.c src/ui.c lib/sds/sds.c lib/minheap/heap.c -largp -o $(TARGET)

clean:
	rm -rf $(BIN_DIR)
	rm -rf build
	rm -f *.exe
	rm -f *.c.bak
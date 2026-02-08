BIN_DIR = bin
TARGET = $(BIN_DIR)/ciphter
TEST_TARGET = $(BIN_DIR)/test_runner

all: $(TARGET) $(TEST_TARGET)

$(TARGET): src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c src/fitness.c src/utils.c
	mkdir -p $(BIN_DIR)
	gcc -g src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c src/fitness.c src/utils.c lib/sds/sds.c lib/minheap/heap.c -largp -o $(TARGET)

$(TEST_TARGET): src/test_runner.c
	mkdir -p $(BIN_DIR)
	gcc -g src/test_runner.c lib/sds/sds.c -o $(TEST_TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -rf $(BIN_DIR)
	rm -rf build
	rm -f *.exe
	rm -f *.c.bak
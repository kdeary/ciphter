main: src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c
	gcc -g src/main.c src/analyzers/analysis_registry.c src/solvers/solver_registry.c lib/sds/sds.c -largp -o bin/ciphter
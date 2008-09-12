#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int run(char *fname) {
	FILE *fp = fopen(fname, "r");
	char ch;

	while(!feof(fp)) {
		ch = fgetc(fp);
		if(ch == '0') {
			printf("Zero at: %X\n", ftell(fp));
		}
	}

	fclose(fp);
}

int main(int argc, char **argv) {
	int val = 1;

	if(argc > 1) {
		val = run(argv[1]);
	}

	return val;
}


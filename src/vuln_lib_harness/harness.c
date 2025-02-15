#include <stdio.h>
#include <stdlib.h>
#include <imgread.h>

int main(int argc,char **argv)
{
    struct Image *img = malloc(sizeof(*img));
	FILE *fp;

	if (argc < 2)
	{
		// Read from STDIN
		fp = stdin;
  	}
	else
	{
		fp = fopen(argv[1], "r");
	}

    fread(img, 1, sizeof(*img), fp);
	fclose(fp);

	process_image(img);

	return 0;
}

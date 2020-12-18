#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

char buf[1204];

void main()
{
	while (1)
	{
		scanf("%s", buf);
		if(!strcmp(buf, "123"))
			printf("ok\n");
		else
			printf("fail\n");
	}

}



#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/types.h>
#include <linux/random.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	int random_fd;
	int ent_count;

	random_fd = open("/dev/random", O_RDONLY);

	if (random_fd < 0)
		return 1;

	if (ioctl(random_fd, RNDGETENTCNT, &ent_count) != 0)
		return 1;

	printf("%d\n", ent_count);

	return 0;
}


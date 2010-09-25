#define hd(p, l) { int i;		\
    for (i = 1; i <= l; i++) {		\
      printf ("%02x ", p[i-1]);		\
      if (i % 8 == 0) printf (" ");	\
      if (i % 16 == 0) printf ("\n"); }	\
    printf ("\n"); }

/* From freeradius-server/src/lib/radius.c */
#include <freeradius/libradius.h>
static void print_hex(RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data) return;

	printf("  Code:\t\t%u\n", packet->data[0]);
	printf("  Id:\t\t%u\n", packet->data[1]);
	printf("  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	printf("  Vector:\t");
	for (i = 4; i < 20; i++) {
		printf("%02x", packet->data[i]);
	}
	printf("\n");

	if (packet->data_len > 20) {
		int total;
		const uint8_t *ptr;
		printf("  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;

			printf("\t\t");
			if (total < 2) { /* too short */
				printf("%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					printf("%02x ", ptr[i]);
				}
				break;
			}

			printf("%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;
			ptr += 2;
			total -= 2;

			for (i = 0; i < attrlen; i++) {
				if ((i > 0) && ((i & 0x0f) == 0x00))
					printf("\t\t\t");
				printf("%02x ", ptr[i]);
				if ((i & 0x0f) == 0x0f) printf("\n");
			}

			if ((attrlen & 0x0f) != 0x00) printf("\n");

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */

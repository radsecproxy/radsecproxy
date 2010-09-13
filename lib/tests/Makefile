CFLAGS = -Wall -g

all: test-blocking

test-blocking: test-blocking.c ../examples/blocking.o ../base.o ../../list.o ../../tlv11.o
	$(CC) $(CFLAGS)  -I .. -I ../examples -o $@ $^

clean:
	-rm *.o test-blocking


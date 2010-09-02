blocking.o: blocking.c blocking.h libradsec-base.h libradsec.h
base.o: base.c libradsec-base.h libradsec.h
test-blocking: test-blocking.c blocking.o base.o
	$(CC) -o $@ $^

doc:
	doxygen

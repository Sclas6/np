OBJS=SearchDevice.o libarp.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=
TARGET=SearchDevice
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	-rm -f ${OBJS} ${TARGET} ${TARGET}.exe


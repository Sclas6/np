OBJS=httpMonitor.o libarp.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=
TARGET=httpMonitor
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	-rm -f ${OBJS} ${TARGET} ${TARGET}.exe


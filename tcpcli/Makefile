TOXCORE_BUILD ?= c-toxcore/build
TOXCORE_SRC  ?= c-toxcore
DEVSYS       ?= $(HOME)/devsys

CFLAGS  := -I$(TOXCORE_SRC) -I$(DEVSYS)/include -DTCP_CONNECTION_ALLOC $(CFLAGS)
LDFLAGS := -L$(TOXCORE_BUILD) -L$(DEVSYS)/lib $(LDFLAGS)
LDLIBS  := -ltoxcore -lsodium -lpthread

tcp_chat: tcp_chat.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

run: tcp_chat
	LD_LIBRARY_PATH=$(DEVSYS)/lib ./tcp_chat

.PHONY: run

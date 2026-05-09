DEVSYS  ?= /tmp/opencode/devsys
CFLAGS  := -I$(DEVSYS)/usr/include -I$(DEVSYS)/usr/include/x86_64-linux-gnu \
           -std=c99 -Wall -Wextra $(CFLAGS)
LDLIBS  := -L$(DEVSYS)/usr/lib/x86_64-linux-gnu -lcurl -lcjson -lsecp256k1 -lcrypto

nostr_chat: nostr_chat.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

nostr_chat_go: nostr_chat.go
	go build -o $@ $<

run: nostr_chat
	LD_LIBRARY_PATH=$(DEVSYS)/usr/lib/x86_64-linux/gcc/x86_64-linux-gnu/14/../../..:$(DEVSYS)/usr/lib/x86_64-linux-gnu ./nostr_chat $(ARGS)

run_go: nostr_chat_go
	./nostr_chat_go $(ARGS)

.PHONY: run run_go clean
clean:
	rm -f nostr_chat nostr_chat_go

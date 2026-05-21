BINDIR ?= bin
GO ?= go
GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDDATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

CMDS := detect peer scanrelay source budgeted-connect budgeted-peer
TARGETS := $(addprefix $(BINDIR)/, $(CMDS))

.PHONY: all clean $(CMDS)

all: $(TARGETS)

$(BINDIR)/%: cmd/%/main.go
	@mkdir -p $(BINDIR)
	$(GO) build -o $@ \
		-ldflags "-X main.gitCommit=$(GITCOMMIT) -X main.buildDate=$(BUILDDATE)" \
		./$<

$(CMDS): %: $(BINDIR)/%

clean:
	rm -rf $(BINDIR)

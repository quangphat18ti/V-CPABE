.PHONY: all build clean setup keygen encrypt decrypt verify-key verify-ciphertext

BINDIR := bin
TOOLS := setup key_generator encryptor decryptor

# Default target - run the full flow demo
all: build
	$(BINDIR)/setup
	@echo ""
	$(BINDIR)/key_generator
	@echo ""
	$(BINDIR)/decryptor --mode=verify-key
	@echo ""
	$(BINDIR)/encryptor
	@echo ""
	$(BINDIR)/decryptor --mode=verify-ciphertext
	@echo ""
	$(BINDIR)/decryptor --mode=decrypt
	@echo "Full flow completed successfully."

# Build all binaries
build: $(TOOLS)
	mkdir -p $(BINDIR)
	go build -o $(BINDIR)/demo main.go

$(TOOLS):
	mkdir -p $(BINDIR)
	go build -o $(BINDIR)/$@ cmd/$@/main.go

setup: build
	$(BINDIR)/setup

keygen: build
	$(BINDIR)/key_generator

encrypt: build
	$(BINDIR)/encryptor

decrypt: build
	$(BINDIR)/decryptor --mode=decrypt

verify-key: build
	$(BINDIR)/decryptor --mode=verify-key

verify-ciphertext: build
	$(BINDIR)/decryptor --mode=verify-ciphertext

clean:
	rm -rf $(BINDIR)
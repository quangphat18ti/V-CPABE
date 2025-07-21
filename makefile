.PHONY: all build clean setup keygen encrypt decrypt verify-key verify-ciphertext

BINDIR := bin
TOOLS := setup key_generator encryptor decryptor create_policy

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
	@echo "Building tools..."
	@go mod tidy
	@mkdir -p $(BINDIR)
	@for tool in $(TOOLS); do \
		go build -o $(BINDIR)/$$tool cmd/$$tool/main.go; \
	done
	@go build -o $(BINDIR)/demo main.go
	@echo "Build completed.\n \n"

$(TOOLS):

setup: build
	$(BINDIR)/setup $(ARGS)

keygen: build
	$(BINDIR)/key_generator $(ARGS)

encrypt: build
	$(BINDIR)/encryptor $(ARGS)

decrypt: build
	$(BINDIR)/decryptor --mode=decrypt $(ARGS)

verify-key: build
	$(BINDIR)/decryptor --mode=verify-key $(ARGS)

verify-ciphertext: build
	$(BINDIR)/decryptor --mode=verify-ciphertext $(ARGS)

clean:
	rm -rf $(BINDIR)
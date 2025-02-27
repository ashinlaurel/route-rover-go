# Define a variable for the path to the Air binary
AIR := $(shell which air)

.PHONY: setup
setup:
	@echo "Checking if Air is installed..."
	@if [ -z "$(AIR)" ]; then \
		echo "Installing Air..."; \
		go install github.com/air-verse/air@latest; \
	else \
		echo "Air is already installed."; \
	fi

.PHONY: dev
dev: setup
	@echo "Starting Air..."
	@air

.PHONY: clean
clean:
	@echo "Cleaning up temporary files..."
	rm -rf tmp

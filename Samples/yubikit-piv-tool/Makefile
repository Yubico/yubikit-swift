BINARY_NAME = yubikit-piv-tool
BUILD_DIR = .build/release
BIN_DIR = bin
ENTITLEMENTS = yubikit-piv-tool.entitlements

.PHONY: all
all: install

.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	swift build -c release

.PHONY: codesign
codesign: build
	@echo "Codesigning $(BINARY_NAME)..."
	codesign --entitlements $(ENTITLEMENTS) -f -s - $(BUILD_DIR)/$(BINARY_NAME)

.PHONY: install
install: codesign
	@echo "Installing $(BINARY_NAME) to $(BIN_DIR)/..."
	mkdir -p $(BIN_DIR)
	cp $(BUILD_DIR)/$(BINARY_NAME) $(BIN_DIR)/

.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf .build $(BIN_DIR)

.PHONY: test
test: install
	@echo "Running tests..."
	cd tests && bats .

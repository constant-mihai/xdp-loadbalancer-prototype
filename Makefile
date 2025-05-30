.PHONY: build
build:
	go generate ./...
	go build -o bin/xlbp ./cmd/xlbp/

.PHONY: run
run:
	go run main.go

.PHONY: test
test:
	go test -v ./...

.PHONY: clean 
clean:
	rm -rf bin/

.PHONY: deps
deps:
	sudo apt update
	sudo apt install -y make build-essential linux-headers-$$(uname -r) libbpf-dev clang llvm linux-tools-common
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

.PHONY: go-deps
go-deps:
	go mod download
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run

.PHONY: docker-build-xlbp
docker-build-xlbp:
	docker build --ssh default -f Dockerfile -t xlbp:latest .

.PHONY: docker-run-xlbp
docker-run-xlbp:
	docker compose run --remove-orphans -d xlbp:latest

.PHONY: docker-run-xlbp-debug
docker-run-xlbp-debug:
	docker compose -f docker-compose.yaml -f docker-compose.debug.yaml run --remove-orphans xlbp 

.PHONY: docker-exec-xlbp
docker-exec-xlbp:
	docker compose exec -it xlbp /bin/bash

.PHONY: docker-build-xlbp-debug
docker-build-xlbp-debug:
	docker build --ssh default -f Dockerfile.debug -t xlbp-debug:latest .

.PHONY: docker-build-trex
docker-build-trex:
	docker build --ssh default -f Dockerfile.trex -t xlbp-trex:latest .

.PHONY: debug
debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up


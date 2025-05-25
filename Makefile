.PHONY: build run test clean go-deps deps lint

build:
	go generate ./...
	go build -o bin/xlbp ./cmd/xlbp/

run:
	go run main.go

test:
	go test -v ./...

clean:
	rm -rf bin/

deps:
	sudo apt update
	sudo apt install -y make build-essential linux-headers-$$(uname -r) libbpf-dev clang llvm linux-tools-common
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

go-deps:
	go mod download
	go mod tidy

lint:
	golangci-lint run

docker-build-xlbp:
	docker build --ssh default -f Dockerfile -t xlbp:latest .

docker-build-trex:
	docker build --ssh default -f Dockerfile.trex -t xlbp-trex:latest .

docker-run:
	docker run xlbp:latest

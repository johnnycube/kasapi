.PHONY: build test cover fmt vet tidy clean

build:
	go build -o kascli ./cmd/kascli

test:
	go test -race -count=1 ./...

cover:
	go test -count=1 -coverprofile=cover.out ./... && go tool cover -func=cover.out | tail -1

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f kascli cover.out

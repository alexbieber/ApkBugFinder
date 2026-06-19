.PHONY: dev scanner web docker-up docker-build install

install:
	npm install
	cd scanner && go mod tidy

dev:
	npm run dev

scanner:
	cd scanner && go run ./cmd/apkbugfinder -serve -addr :8080

web:
	npm run dev

docker-build:
	docker compose build

docker-up:
	docker compose up --build

docker-scanner:
	docker compose up --build scanner

build:
	npm run build
	cd scanner && go build -o ../bin/apkbugfinder ./cmd/apkbugfinder

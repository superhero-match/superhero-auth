prepare:
	go mod download

run:
	go build -o bin/main cmd/api/main.go
	./bin/main

build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o bin/main cmd/api/main.go
	chmod +x bin/main

dkb:
	docker build -t superhero-auth .

dkr:
	docker run -p "9100:9100" -p "8290:8290" superhero-auth

launch: dkb dkr

api-log:
	docker logs superhero-auth -f

rmc:
	docker rm -f $$(docker ps -a -q)

rmi:
	docker rmi -f $$(docker images -a -q)

clear: rmc rmi

api-ssh:
	docker exec -it superhero-auth /bin/bash

PHONY: prepare build dkb dkr launch api-log api-ssh rmc rmi clear
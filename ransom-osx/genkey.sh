openssl genpkey -algorithm X25519 -out private.pem

openssl pkey -in private.pem -outform DER         | tail -c 32 > private.key
openssl pkey -in private.pem -pubout -outform DER | tail -c 32 > locker/public.key

rm private.pem

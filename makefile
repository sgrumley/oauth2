# TLS
gen-cert:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Server 
server-start:
	go run ./cmd/server/... &

# Front end
frontend-start:
	go run ./cmd/redirectmock/... &

# Client
auth-code-flow: clean server-start frontend-start
	go run ./cmd/client/... ;

clean:
	-pkill -f "go run ./cmd/server/..." || true
	-pkill -f "go run ./cmd/redirectmock/..." || true
	# Wait a moment to ensure ports are freed
	sleep 2

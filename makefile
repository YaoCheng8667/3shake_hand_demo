all: server client

server_dependence=packet_generator.h server.cc
client_dependence=packet_generator.h client.cc

server: $(server_dependence)
	g++ -o server $(server_dependence)

tcpser: $(client_dependence)
	g++ -o client $(client_dependence)
	
clean:
	rm server client
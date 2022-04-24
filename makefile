GCC = gcc
FLAGS = -lpcap

compile: ipk-sniffer.c ipk-sniffer.h
	$(GCC) ipk-sniffer.c -o ipk-sniffer $(FLAGS)

run1: compile
	./ipk-sniffer -i eth0

run2: compile
	./ipk-sniffer -i eth0 -n 10

run3: compile
	./ipk-sniffer -i eth0 -n 5 --tcp

run4: compile
	./ipk-sniffer -i eth0 -n 

run5: compile
	./ipk-sniffer -i eth -n 5

run6: compile
	./ipk-sniffer -i eth0 -n 5 

short: compile
	./ipk-sniffer -i eth0 -n 2 -t -u -a -m -p 23

long: compile
	./ipk-sniffer --interface eth0 --num 5 --tcp --udp --arp --icmp --port 23 

run7: compile
	./ipk-sniffer -i eth0 -n 10 --icmp

run8: compile
	./ipk-sniffer -i eth0 -n 10 --arp

helpshort: compile
	./ipk-sniffer -h

helplong: compile
	./ipk-sniffer --help

clean:
	rm ipk-sniffer

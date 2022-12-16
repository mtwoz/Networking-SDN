#!/bin/zsh

echo "This is a script to get enough TCP handshake packets in client side for CAN201 Networking Assessment."
echo "starting..."

for i in {1..100}; do
	echo $i
	nohup python client.py >> cmd.out 2>&1 & echo $! > cmd.pid
	sleep 1
	kill -9 `cat cmd.pid`
	sleep 1
done

echo "closing..."

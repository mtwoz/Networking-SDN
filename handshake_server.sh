#!/bin/zsh

echo "This is a script to get enough TCP handshake packets in server side for CAN201 Networking Assessment."
echo "starting..."

flag=`ps -aux | grep /home/whoismz/Documents/XJTLU/CAN201/CW_2/server.py | grep -v "grep" | wc -l`

while true
do
        if [ $flag -eq 0 ]
        then
                nohup python server.py
        fi
done

echo "closing..."

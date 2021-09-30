#!/bin/bash

loops=$1

for i in `ls -tr` ; do

   ./radcl_sim  --server-ip 192.168.10.156  --user-conf users.conf --password radiusproxy --my-ip 10.251.236.248 --ue 1000

done



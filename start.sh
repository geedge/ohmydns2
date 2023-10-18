#!/bin/bash

cd ./plugin/v64dns/analyze/pb/
nohup python3 -u analyzer.py >/dev/null 2>error.log  2>&1 &
# python3 ./analyzer.py > python.log
cd /project/ohmydns2
./ohmydns2
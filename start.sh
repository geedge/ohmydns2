#!/bin/bash

cd ./plugin/v64dns/analyze/pb/
python3 ./analyzer.py &
cd /project/ohmydns2
./ohmydns2
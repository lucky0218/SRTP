#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <PID>"
  exit 1
fi

file_name="$1"

echo "------" >> "$file_name"

for ((i=1; i<=50; i++))
do
    echo "Running get_time.sh iteration $i"
    bash get_time.sh 385 $file_name
done

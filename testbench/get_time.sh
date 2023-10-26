#!/bin/bash

# Check if the PID argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <PID>"
  exit 1
fi

if [ -z "$2" ]; then
  echo "Usage: $0 <file name>"
  exit 1
fi

pid="$1"
stat_file="/proc/$pid/stat"
output_file="$2"

# Check if the stat file exists
if [ ! -f "$stat_file" ]; then
  echo "Stat file not found: $stat_file"
  exit 1
fi

# Get the initial values of utime and stime
initial_utime=$(awk '{print $14}' "$stat_file")
initial_stime=$(awk '{print $15}' "$stat_file")

# Wait for 5 seconds
sleep 5

# Read the updated values of utime and stime
updated_utime=$(awk '{print $14}' "$stat_file")
updated_stime=$(awk '{print $15}' "$stat_file")

# Calculate the delta in utime and stime
delta_utime=$((updated_utime - initial_utime))
delta_stime=$((updated_stime - initial_stime))

# Calculate the total running time
total_time=$((delta_utime + delta_stime))

# Output the delta values and total running time to the file
echo "Delta utime: $delta_utime"
echo "Delta stime: $delta_stime"
echo "$total_time" >> "$output_file"



#!/bin/bash
find /sys -name "*virtual*carrier*" -exec echo "$1" > {} \; 
find /sys -name "*virtual*carrier*" -exec cat {} \; 
find /sys -name "*physical*carrier*" -exec echo "$1" > {} \; 
find /sys -name "*physical*carrier*" -exec cat {} \; 

#!/bin/bash
sudo iw dev wlan$1 interface add moni$1 type monitor
sudo ifconfig wlan$1 down
sudo ifconfig moni$1 up
sudo iw dev moni$1 set channel 11
sudo ifconfig wlan$1 down

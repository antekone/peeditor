#!/bin/bash
# 
# This file is a part of PED.
#
# run
# 
# Created on: 2008-08-08
# Author: antek

file="/home/antek/NetBeansProjects/ped/res/wmp.dll"

PED="../Debug/ped"
ARGS="-D 12 -f $file"

if [ ! -x $PED ]; then
	echo No executable in path: $PED.
	exit 1
fi
  
$PED $ARGS

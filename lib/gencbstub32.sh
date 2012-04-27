#!/bin/bash

# generate callback-stubs-32.S

if [ $# -ne 1 ] ; then
	echo usage bach gencbstub32.sh num
	exit 1
fi

echo ".align  16,0xcc"

for (( i=0 ; i<$1 ; i++ )) ; do
	if [ $i -le 1 ] ; then
		echo ".globl  cj_callback_stub$i"
		echo ".type   cj_callback_stub$i, @function"
		echo "cj_callback_stub$i:"
	fi
	echo "leal    4(%esp), %eax"
	echo "pushl   %eax"
	echo "pushl   \$$i"
	echo "call    child_callback"
	echo "addl    \$8, %esp"
	echo "ret"
done

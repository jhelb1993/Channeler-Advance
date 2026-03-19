#!/usr/bin/env bash

AS=arm-none-eabi-as
OBJCOPY=arm-none-eabi-objcopy

function isInPath()
{
retval=1
IFS_=$IFS  
IFS=:
for directory in $PATH
do
	if [[ -x ${directory}/${1} ]]
	then
		retval=0
		break
	fi
done
IFS=$IFS_
return $retval
}


isInPath ${AS}
let res=$?
isInPath ${OBJCOPY}
let res+=$?
dst=$2

if [[ ${1} = "" ]]
then
	echo "Lil' ARM/THUMB Assembler Shell Script"
	echo "Written by JZW"
	echo
	echo "Usage: ./thumb.sh source.[asm|s] [output.bin]"
	echo
elif [[ "${1##*.}" = "s"||"${1##*.}" = "asm" ]]
then
	if [[ ! -f ${1} ]]
	then
		echo "Cannot assemble ${1}: the file does not exist."
	elif [[ $(stat -c "%s" ${1}) = 0 ]]
	then
		echo "Cannot assemble ${1}: the file is empty."
	elif [[ res -gt 0 ]]
	then
		echo "Compiler Missing: make sure that you have devkitarm bins in your path variable."
	else
	 	if [[ -f "a.out" ]]
		then
			rm a.out
		fi
		$(${AS} -mthumb -mthumb-interwork ${1})
		if [[ $? = 0 ]]
		then
			if [[ ${2} = "" ]]
			then
				dst=${1%%.*}.bin
			fi
			$(${OBJCOPY} -O binary a.out ${dst})
			if [[ $? != 0 || ! -f ${dst} ]]
			then
				rm a.out
				echo "Cannot assemble ${1}: An error occurred."
			else
				echo "Assembled successfully."
			fi
			
		elif [[ -f "a.out" ]]
		then
			rm a.out
			echo "Cannot assemble ${1}: An error occurred."
		else
			echo "Cannot assemble ${1}: An error occurred."
		fi
	fi
else
	echo "The input file should have the extension .asm or .s."
fi

#!/usr/bin/env bash

AS=arm-none-eabi-as
LD=arm-none-eabi-ld
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
isInPath ${LD}
let res+=$?
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
	if [[ ! -f "${1}" ]]
	then
		echo "Cannot assemble ${1}: the file does not exist."
	elif [[ ! -s "${1}" ]]
	then
		echo "Cannot assemble ${1}: the file is empty."
	elif [[ $res -gt 0 ]]
	then
		echo "Compiler Missing: make sure that you have devkitarm bins in your path variable."
	else
		obj_o="${1%.*}.o"
		obj_elf="${1%.*}.elf"
		rm -f "${obj_o}" "${obj_elf}"
		"${AS}" -mthumb -mthumb-interwork -o "${obj_o}" "${1}"
		if [[ $? = 0 ]]
		then
			"${LD}" -nostdlib --section-start=.text=0 -o "${obj_elf}" "${obj_o}"
			if [[ $? != 0 ]]
			then
				rm -f "${obj_o}" "${obj_elf}"
				echo "Cannot assemble ${1}: link failed (arm-none-eabi-ld)."
			else
				if [[ ${2} = "" ]]
				then
					dst=${1%%.*}.bin
				fi
				"${OBJCOPY}" -O binary "${obj_elf}" "${dst}"
				if [[ $? != 0 || ! -f ${dst} ]]
				then
					rm -f "${obj_o}" "${obj_elf}"
					echo "Cannot assemble ${1}: An error occurred."
				else
					rm -f "${obj_o}" "${obj_elf}"
					echo "Assembled successfully."
				fi
			fi
		else
			rm -f "${obj_o}" "${obj_elf}"
			echo "Cannot assemble ${1}: An error occurred."
		fi
	fi
else
	echo "The input file should have the extension .asm or .s."
fi

#!/bin/bash
#
# This is a script to parse the load.cmm automatically and use the crash tool
# Used by Qualcomm internal
# Any questions, please contact <jiacangl@qti.qualcomm.com>
#

#export CRASH_HOME=/var/www/html/sdc/soft/crash_/crash
export CRASH_HOME=/home/ysg/crash
export CRASH_EXTENSIONS=$CRASH_HOME/extensions
SYMBOL="$1"
FILENAME="$2"
# Usage function
usage()
{
    echo -e "Usage: $0 vmlinux load.cmm \n"
    echo -e "       $0 vmlinux load.cmm <--minimal> <--no_data_debug><...>\n"
    exit
}

para="$CRASH_HOME/crash "
blank=" "
comma=","
s=" "

if [ $# -lt 2 ]; then
usage
fi

if [[ "$2" != "load.cmm" ]]; then
usage
fi

while [ "$#" -ge "2" ];do
    t=$3
    s=${s}${t}${blank}
    shift
done

para=${para}${SYMBOL}${blank}
a=0
for i in `cat $FILENAME`
do
    if [ $a -eq 1 ]
        then
            para=${para}${i},
            a=0
    fi

    str1=${i:0:4}
    if test "$str1" = "DDRC"
        then
            para=${para}${i}@
            a=1
    fi
done


aa=$(od -A x -t x -j 0x3f6d0 -N 0x10 OCIMEM.BIN)
cc=$(od -A x -t x -j 0x2a6d0 -N 0x10 OCIMEM.BIN)
bb=$(od -A x -t x -j 0x6d0 -N 0x10 OCIMEM.BIN)
sm6125=$(od -A x -t x -j 0x256d0 -N 0x10 OCIMEM.BIN)
sm7250=$(od -A x -t x -j 0x2b6d0 -N 0x10 OCIMEM.BIN)
str1=${aa:7:8}
str2=${bb:7:8}
str3=${cc:7:8}
sm6125_str=${sm6125:7:8}
sm7250_str=${sm7250:7:8}
echo $str1
echo $str2
echo $str3
echo $sm6125_str
echo $sm7250_str


if test "$str1" = "dead4ead"
    then
        echo "qcom kaslr is enabled (0x3f6d0)"
        str5=" --kaslr=0x"
        str6=${aa:16:8}
        str7=${aa:25:8}
        s=${str5}${str7}${str6}${s}
elif test "$str2" = "dead4ead"
    then
	echo "qcom kaslr is enabled (0x6d0)"
        str5=" --kaslr=0x"
        str6=${bb:16:8}
        str7=${bb:25:8}
        s=${str5}${str7}${str6}${s}
elif test "$str3" = "dead4ead"
    then
	echo "qcom kaslr is enabled (0x6d0)"
        str5=" --kaslr=0x"
        str6=${cc:16:8}
        str7=${cc:25:8}
        s=${str5}${str7}${str6}${s}

elif test "$sm6125_str" = "dead4ead"
    then
	echo "qcom kaslr is enabled (0x6d0)"
        str5=" --kaslr=0x"
        str6=${sm6125:16:8}
        str7=${sm6125:25:8}
        s=${str5}${str7}${str6}${s}

elif test "$sm7250_str" = "dead4ead"
    then
	echo "qcom kaslr is enabled (0x2b6d0)"
	str5=" --kaslr=0x"
	str6=${sm7250:16:8}
	str7=${sm7250:25:8}
	s=${str5}${str7}${str6}${s}

fi


b=${#para}
para=${para:0:(b-1)}
para=${para}${s}
echo $para
eval $para

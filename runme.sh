CRASH_PATH=/home/ysg/crash
Vmlinux=`find -name vmlinux`

echo $Vmlinux

$CRASH_PATH/crash.sh $Vmlinux load.cmm --machdep vabits_actual=39


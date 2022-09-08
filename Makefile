# This makefile is just for debugging/test purposes
# It is not needed at all for anything
# Should probably just be excluded from the git repo completely
test :
	odin run nbnet.odin -file -define:DEBUG=YES
	rm *.bin
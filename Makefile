# This makefile is just for debugging/test purposes
# It is not needed at all for anything
# Should probably just be excluded from the git repo completely
rm_bin :
	rm nbnet/.bin

_test :
	odin run nbnet -define:NBN_DEBUG=1
test : _test rm_bin

_win_test :
	odin run nbnet -define:NBN_DEBUG=1 -target:windows_amd64
win_test : _win_test rm_bin
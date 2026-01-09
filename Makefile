# Include gomk if it's been checked-out: git submodule update --init
-include gomk/main.mk
#-include local/Makefile

clean: clean-default
	@rm -f ./*.pfx

obj-m += avast.o

PWD := $(CURDIR)
BUILD_COMMAND := make -C /lib/modules/$(shell uname -r)/build M=$(PWD)
all:
	$(BUILD_COMMAND) modules
clean:
	$(BUILD_COMMAND) clean
compile_commands.json:
	$(BUILD_COMMAND) compile_commands.json

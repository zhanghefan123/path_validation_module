# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/zhf/Projects/srv6_kernel

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zhf/Projects/srv6_kernel/build

# Include any dependencies generated for this target.
include CMakeFiles/dummy.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/dummy.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/dummy.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/dummy.dir/flags.make

CMakeFiles/dummy.dir/tools.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/tools.c.o: ../tools.c
CMakeFiles/dummy.dir/tools.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/dummy.dir/tools.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/tools.c.o -MF CMakeFiles/dummy.dir/tools.c.o.d -o CMakeFiles/dummy.dir/tools.c.o -c /home/zhf/Projects/srv6_kernel/tools.c

CMakeFiles/dummy.dir/tools.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/tools.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/tools.c > CMakeFiles/dummy.dir/tools.c.i

CMakeFiles/dummy.dir/tools.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/tools.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/tools.c -o CMakeFiles/dummy.dir/tools.c.s

CMakeFiles/dummy.dir/module_starter.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/module_starter.c.o: ../module_starter.c
CMakeFiles/dummy.dir/module_starter.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/dummy.dir/module_starter.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/module_starter.c.o -MF CMakeFiles/dummy.dir/module_starter.c.o.d -o CMakeFiles/dummy.dir/module_starter.c.o -c /home/zhf/Projects/srv6_kernel/module_starter.c

CMakeFiles/dummy.dir/module_starter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/module_starter.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/module_starter.c > CMakeFiles/dummy.dir/module_starter.c.i

CMakeFiles/dummy.dir/module_starter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/module_starter.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/module_starter.c -o CMakeFiles/dummy.dir/module_starter.c.s

CMakeFiles/dummy.dir/ftrace_hook_api.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/ftrace_hook_api.c.o: ../ftrace_hook_api.c
CMakeFiles/dummy.dir/ftrace_hook_api.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/dummy.dir/ftrace_hook_api.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/ftrace_hook_api.c.o -MF CMakeFiles/dummy.dir/ftrace_hook_api.c.o.d -o CMakeFiles/dummy.dir/ftrace_hook_api.c.o -c /home/zhf/Projects/srv6_kernel/ftrace_hook_api.c

CMakeFiles/dummy.dir/ftrace_hook_api.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/ftrace_hook_api.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/ftrace_hook_api.c > CMakeFiles/dummy.dir/ftrace_hook_api.c.i

CMakeFiles/dummy.dir/ftrace_hook_api.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/ftrace_hook_api.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/ftrace_hook_api.c -o CMakeFiles/dummy.dir/ftrace_hook_api.c.s

CMakeFiles/dummy.dir/hook_functions.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/hook_functions.c.o: ../hook_functions.c
CMakeFiles/dummy.dir/hook_functions.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/dummy.dir/hook_functions.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/hook_functions.c.o -MF CMakeFiles/dummy.dir/hook_functions.c.o.d -o CMakeFiles/dummy.dir/hook_functions.c.o -c /home/zhf/Projects/srv6_kernel/hook_functions.c

CMakeFiles/dummy.dir/hook_functions.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/hook_functions.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/hook_functions.c > CMakeFiles/dummy.dir/hook_functions.c.i

CMakeFiles/dummy.dir/hook_functions.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/hook_functions.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/hook_functions.c -o CMakeFiles/dummy.dir/hook_functions.c.s

CMakeFiles/dummy.dir/resolve_function_address.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/resolve_function_address.c.o: ../resolve_function_address.c
CMakeFiles/dummy.dir/resolve_function_address.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/dummy.dir/resolve_function_address.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/resolve_function_address.c.o -MF CMakeFiles/dummy.dir/resolve_function_address.c.o.d -o CMakeFiles/dummy.dir/resolve_function_address.c.o -c /home/zhf/Projects/srv6_kernel/resolve_function_address.c

CMakeFiles/dummy.dir/resolve_function_address.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/resolve_function_address.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/resolve_function_address.c > CMakeFiles/dummy.dir/resolve_function_address.c.i

CMakeFiles/dummy.dir/resolve_function_address.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/resolve_function_address.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/resolve_function_address.c -o CMakeFiles/dummy.dir/resolve_function_address.c.s

CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o: ../hook_tcp_v4_rcv.c
CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o -MF CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o.d -o CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o -c /home/zhf/Projects/srv6_kernel/hook_tcp_v4_rcv.c

CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/hook_tcp_v4_rcv.c > CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.i

CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/hook_tcp_v4_rcv.c -o CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.s

CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o: ../self_defined_tcp_v4_do_rcv.c
CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o -MF CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o.d -o CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o -c /home/zhf/Projects/srv6_kernel/self_defined_tcp_v4_do_rcv.c

CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/self_defined_tcp_v4_do_rcv.c > CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.i

CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/self_defined_tcp_v4_do_rcv.c -o CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.s

CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o: CMakeFiles/dummy.dir/flags.make
CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o: ../self_defined_tcp_rcv_established.c
CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o: CMakeFiles/dummy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o -MF CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o.d -o CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o -c /home/zhf/Projects/srv6_kernel/self_defined_tcp_rcv_established.c

CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zhf/Projects/srv6_kernel/self_defined_tcp_rcv_established.c > CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.i

CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zhf/Projects/srv6_kernel/self_defined_tcp_rcv_established.c -o CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.s

# Object files for target dummy
dummy_OBJECTS = \
"CMakeFiles/dummy.dir/tools.c.o" \
"CMakeFiles/dummy.dir/module_starter.c.o" \
"CMakeFiles/dummy.dir/ftrace_hook_api.c.o" \
"CMakeFiles/dummy.dir/hook_functions.c.o" \
"CMakeFiles/dummy.dir/resolve_function_address.c.o" \
"CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o" \
"CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o" \
"CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o"

# External object files for target dummy
dummy_EXTERNAL_OBJECTS =

dummy: CMakeFiles/dummy.dir/tools.c.o
dummy: CMakeFiles/dummy.dir/module_starter.c.o
dummy: CMakeFiles/dummy.dir/ftrace_hook_api.c.o
dummy: CMakeFiles/dummy.dir/hook_functions.c.o
dummy: CMakeFiles/dummy.dir/resolve_function_address.c.o
dummy: CMakeFiles/dummy.dir/hook_tcp_v4_rcv.c.o
dummy: CMakeFiles/dummy.dir/self_defined_tcp_v4_do_rcv.c.o
dummy: CMakeFiles/dummy.dir/self_defined_tcp_rcv_established.c.o
dummy: CMakeFiles/dummy.dir/build.make
dummy: CMakeFiles/dummy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zhf/Projects/srv6_kernel/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking C executable dummy"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/dummy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/dummy.dir/build: dummy
.PHONY : CMakeFiles/dummy.dir/build

CMakeFiles/dummy.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/dummy.dir/cmake_clean.cmake
.PHONY : CMakeFiles/dummy.dir/clean

CMakeFiles/dummy.dir/depend:
	cd /home/zhf/Projects/srv6_kernel/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhf/Projects/srv6_kernel /home/zhf/Projects/srv6_kernel /home/zhf/Projects/srv6_kernel/build /home/zhf/Projects/srv6_kernel/build /home/zhf/Projects/srv6_kernel/build/CMakeFiles/dummy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/dummy.dir/depend


# BIG THANK YOU TO THE ORIGINAL AUTHOR
# https://gitlab.com/christophacham/cmake-kernel-module

# Find the kernel release
# 北航服务器设置
#set(KERNEL_RELEASE "5.19.0-41-generic")
# 树莓派设置
set(KERNEL_RELEASE "5.19.17")

#execute_process(
#        COMMAND uname -r
#        OUTPUT_VARIABLE KERNEL_RELEASE
#        OUTPUT_STRIP_TRAILING_WHITESPACE
#)

# Find the headers
find_path(KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
        )

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")

if (KERNELHEADERS_DIR)
    set(KERNELHEADERS_INCLUDE_DIRS
            ${KERNELHEADERS_DIR}/include
# 北航服务器版本
#            ${KERNELHEADERS_DIR}/arch/x86/include
            ${KERNELHEADERS_DIR}/arch/arm64/include
            CACHE PATH "Kernel headers include dirs"
            )
    set(KERNELHEADERS_FOUND 1 CACHE STRING "Set to 1 if kernel headers were found")
else (KERNELHEADERS_DIR)
    set(KERNELHEADERS_FOUND 0 CACHE STRING "Set to 1 if kernel headers were found")
endif (KERNELHEADERS_DIR)

mark_as_advanced(KERNELHEADERS_FOUND)
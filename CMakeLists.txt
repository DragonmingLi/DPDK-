cmake_minimum_required(VERSION 2.8.12)
project(mydpdk)

add_compile_options(-fPIC -O0 -g -Wall -march=native -fgnu89-inline -Wl,--hash-style=sysv)
set(Demo ./main.c ./mydpdk.c)
set(DPDK_INCLUDE "/home/lmq/mydpdk_final/NIDS_DPDK/dpdk-stable-16.11.8/x86_64-native-linuxapp-gcc/include")
#find_library(DPDK_LIB dpdk  /home/lmq/dpdk-stable-16.11.8/x86_64-native-linuxapp-gcc/lib)
set(DPDK_LIB "/home/lmq/mydpdk_final/NIDS_DPDK/dpdk-stable-16.11.8/x86_64-native-linuxapp-gcc/lib/*.so")
#link_libraries(${DPDK_LIB})
include_directories(/home/lmq/mydpdk_final/NIDS_DPDK/dpdk-stable-16.11.8/x86_64-native-linuxapp-gcc/include)
#link_directories(${/home/lmq/dpdk-stable-16.11.8/x86_64-native-linuxapp-gcc/lib})


add_executable(mydpdk ${Demo})

file(GLOB dpdklibs ${DPDK_LIB})

#link_libraries(${dpdklibs})
#target_link_libraries(mydpdk  ${DPDK_LIB})
target_link_libraries(mydpdk  ${dpdklibs})


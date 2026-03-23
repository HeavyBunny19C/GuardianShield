cmake_minimum_required(VERSION 3.20)
project(GuardMonitor C)

if(WDK_FOUND)
    wdk_add_driver(GuardMonitor
        WDM
        WINVER 0x0A00
        SOURCES
            src/guard_monitor.c
            src/process_notify.c
            src/image_notify.c
            src/communication.c
    )

    target_include_directories(GuardMonitor PRIVATE
        include
        ../shared
    )

    target_compile_definitions(GuardMonitor PRIVATE
        POOL_NX_OPTIN=1
    )

else()
    message(STATUS "WDK not available - GuardMonitor as INTERFACE target (IDE only)")

    add_library(GuardMonitor INTERFACE)
    target_include_directories(GuardMonitor INTERFACE include ../shared)

    set(GUARDMONITOR_SOURCES
        src/guard_monitor.c
        src/process_notify.c
        src/image_notify.c
        src/communication.c
        include/guard_monitor.h
        ../shared/guardian_ioctl.h
    )
    add_custom_target(GuardMonitor_Sources SOURCES ${GUARDMONITOR_SOURCES})
endif()

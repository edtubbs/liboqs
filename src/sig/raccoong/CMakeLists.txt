# SPDX-License-Identifier: MIT

set(_RACCOONG_OBJS "")

if(OQS_ENABLE_SIG_raccoon_g_44)
    add_library(raccoong_44_ref OBJECT sig_raccoong_44.c raccoong.c)
    set(_RACCOONG_OBJS ${_RACCOONG_OBJS} $<TARGET_OBJECTS:raccoong_44_ref>)
endif()

set(RACCOONG_OBJS ${_RACCOONG_OBJS} PARENT_SCOPE)

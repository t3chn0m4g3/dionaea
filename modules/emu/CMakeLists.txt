# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

set(
  module_emu_SRCS
  module.c
  detect.c
  emulate.c
  profile.c
  hooks.c
  trim.c
)

include_directories (..)
include_directories (../../include)
include_directories (../../)
include_directories (${GLIB2_INCLUDE_DIRS})
include_directories (${LIBEMU_INCLUDE_DIRS})
include_directories (${CMAKE_CURRENT_BINARY_DIR}/../..)

add_library(module_emu MODULE ${module_emu_SRCS})

add_dependencies(
  module_emu
  dionaea
)

set_target_properties(
  module_emu PROPERTIES
  OUTPUT_NAME emu
  PREFIX ""
)

if(NOT DIONAEA_BUNDLED_LIBEMU)
  # system libemu from pkg-config
  target_link_directories(module_emu PRIVATE ${LIBEMU_LIBRARY_DIRS})
endif()

if(DIONAEA_BUNDLED_LIBEMU)
  # The static libemu has many global symbols that do not start with emu_
  # (known_dlls, reg_table, ...): do not export them from the module, so they
  # can never be taken over by a symbol of the same name in dionaea.
  target_link_options(module_emu PRIVATE -Wl,--exclude-libs,ALL)
endif()

# Bundled: the static library target emu, its include directory comes with it
target_link_libraries(
  module_emu ${LIBEMU_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_emu
  LIBRARY DESTINATION ${DIONAEA_MODDIR}
)

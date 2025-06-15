# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\lofswap_wallet_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\lofswap_wallet_autogen.dir\\ParseCache.txt"
  "lofswap_wallet_autogen"
  )
endif()

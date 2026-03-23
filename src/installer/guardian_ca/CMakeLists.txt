# GuardianShield - WiX Custom Action DLL
# Exports: ValidateInstallKey, CopyConfigFiles

add_library(guardian_ca SHARED
    guardian_ca.cpp
    guardian_ca.def
)

target_compile_definitions(guardian_ca PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(guardian_ca PRIVATE
    msi
    bcrypt
    advapi32
    shlwapi
)

set_target_properties(guardian_ca PROPERTIES
    OUTPUT_NAME "guardian_ca"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)

install(TARGETS guardian_ca RUNTIME DESTINATION bin)

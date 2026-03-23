# GuardianShield MSI Installer Configuration
#
# This is primarily integrated through CPack WIX generator from the root CMakeLists.txt.
# The WiX source files here define the custom installer UI and behavior.
#
# Build: cmake --build . --target package
# Or:    cpack -G WIX

set(INSTALLER_WXS_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/GuardianShield.wxs
    ${CMAKE_CURRENT_SOURCE_DIR}/InstallDlg.wxs
)

# Make installer sources visible in IDE
add_custom_target(InstallerSources SOURCES ${INSTALLER_WXS_FILES})

# Custom Action DLL
add_subdirectory(guardian_ca)

# Export paths for CPack configuration
set(GUARDIAN_WXS_MAIN "${CMAKE_CURRENT_SOURCE_DIR}/GuardianShield.wxs" PARENT_SCOPE)
set(GUARDIAN_WXS_UI "${CMAKE_CURRENT_SOURCE_DIR}/InstallDlg.wxs" PARENT_SCOPE)

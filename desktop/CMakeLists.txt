cmake_minimum_required(VERSION 3.21)

project(blackbag-desktop
  VERSION 2.5.0
  DESCRIPTION "Credential command deck for the black-bag engine"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Network Svg)

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(blackbag-desktop
  src/main.cpp
  src/app.cpp
  src/app.hpp
  src/datastream.cpp
  src/datastream.hpp
  src/fileview.cpp
  src/fileview.hpp
  src/process.cpp
  src/process.hpp
)

target_compile_definitions(blackbag-desktop
  PRIVATE BLACKBAG_DESKTOP_VERSION="${PROJECT_VERSION}")

# The generated QML type registrations include the headers by bare name.
target_include_directories(blackbag-desktop PRIVATE src)

# The QML lives in qml/ on disk but at the module root in the resource tree, so
# `import "Model.js"` and the singleton lookups resolve the same way they do in
# the plugin's flat directory. That is what lets Cockpit.qml, Editor.qml and
# Model.js be the same files in both surfaces.
foreach(qml_file Main.qml Cockpit.qml Editor.qml Onboard.qml Recover.qml Manage.qml Consent.qml DeckMetrics.qml
                 Color.qml Style.qml Util.qml InputField.qml Model.js)
  set_source_files_properties(qml/${qml_file}
    PROPERTIES QT_RESOURCE_ALIAS ${qml_file})
endforeach()

# Model.js is imported by relative path from the QML that needs it, not as a
# module type, so it gets no qmldir entry. Its `.pragma library` already makes
# it one shared instance rather than one per importing document.
set_source_files_properties(qml/Model.js
  PROPERTIES QT_QML_SKIP_QMLDIR_ENTRY TRUE)

# One palette, one metric scale, one colour helper for the whole surface --
# not a copy per consumer.
set_source_files_properties(qml/Color.qml qml/Style.qml qml/Util.qml
  PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(blackbag-desktop
  URI BlackBag
  VERSION 1.0
  QML_FILES
    qml/Main.qml
    qml/Cockpit.qml
    qml/Editor.qml
    qml/Onboard.qml
    qml/Recover.qml
    qml/Manage.qml
    qml/Consent.qml
    qml/DeckMetrics.qml
    qml/Color.qml
    qml/Style.qml
    qml/Util.qml
    qml/InputField.qml
    qml/Model.js
)

qt_add_resources(blackbag-desktop "appicon"
  PREFIX "/icons"
  BASE packaging
  FILES packaging/black-bag.svg)

target_link_libraries(blackbag-desktop PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Qml
  Qt6::Quick
  Qt6::QuickControls2
  Qt6::Network
  Qt6::Svg
)

include(GNUInstallDirs)

install(TARGETS blackbag-desktop
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES packaging/dev.blackbag.Deck.desktop
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications)

install(FILES packaging/black-bag.svg
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
  RENAME dev.blackbag.Deck.svg)

install(FILES packaging/dev.blackbag.Deck.metainfo.xml
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/metainfo)

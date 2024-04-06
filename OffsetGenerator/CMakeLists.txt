cmake_minimum_required(VERSION 3.5)

project(OffsetGenerator LANGUAGES C)

add_compile_options(-Wall -Wextra)
add_executable(OffsetGenerator main.c)
target_link_libraries(OffsetGenerator -static)
install(TARGETS OffsetGenerator
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

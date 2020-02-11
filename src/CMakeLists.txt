#add_library(mapping_natur40_base_lib OBJECT
#        )
#target_include_directories(mapping_natur40_base_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
#target_include_directories(mapping_natur40_base_lib PRIVATE ${MAPPING_CORE_PATH}/src)

#add_library(mapping_natur40_operators_lib OBJECT
#        )
#target_include_directories(mapping_natur40_operators_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
#target_include_directories(mapping_natur40_operators_lib PRIVATE ${MAPPING_CORE_PATH}/src)

add_library(mapping_natur40_services_lib OBJECT
        services/natur40.cpp
        )

target_link_libraries(mapping_natur40_services_lib OpenSSL::Crypto)

target_include_directories(mapping_natur40_services_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(mapping_natur40_services_lib PRIVATE ${MAPPING_CORE_PATH}/src)

target_include_directories(mapping_natur40_services_lib PUBLIC ${cpp-jwt_SOURCE_DIR}/include)

#target_include_directories(mapping_natur40_operators_lib PRIVATE ${Boost_INCLUDE_DIRS})

#target_include_directories(mapping_natur40_base_lib PRIVATE ${jsoncpp_SOURCE_DIR}/include)
#target_include_directories(mapping_natur40_operators_lib PRIVATE ${jsoncpp_SOURCE_DIR}/include)
target_include_directories(mapping_natur40_services_lib PRIVATE ${jsoncpp_SOURCE_DIR}/include)
#target_include_directories(mapping_natur40_base_lib PRIVATE ${cpptoml_SOURCE_DIR}/include)
#target_include_directories(mapping_natur40_operators_lib PRIVATE ${cpptoml_SOURCE_DIR}/include)
target_include_directories(mapping_natur40_services_lib PRIVATE ${cpptoml_SOURCE_DIR}/include)

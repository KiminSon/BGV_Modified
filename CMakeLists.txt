# CMakeList.txt: bgv_modified에 대한 CMake 프로젝트, 여기에 소스를 포함하고
# 프로젝트 특정 논리를 정의합니다.
#
cmake_minimum_required (VERSION 3.8)

project ("bgv_modified")

# 라이브러리 경로 설정
set(SEAL_DIR "C:/Users/user/Desktop/mpc/SEAL/build")
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD")

# 라이브러리를 찾습니다. 이 줄을 추가하세요.
find_package(SEAL REQUIRED PATHS ${SEAL_DIR})
find_package(OpenSSL REQUIRED)

# 이 프로젝트의 실행 파일에 소스를 추가합니다.
add_executable (bgv_modified "main.cpp" "bgv_modified.h" "examples.h" "modules/bgv/BGVBuilder.cpp" "modules/bgv/BGVSeal.cpp" "modules/bgv/BGVSeal.h" "modules/random/RandomGenerator.cpp" "modules/random/RandomGenerator.h")

# 라이브러리를 프로젝트에 링크합니다. 이 줄을 추가하세요.
target_link_libraries(bgv_modified PRIVATE SEAL::seal)
target_include_directories(bgv_modified PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bgv_modified PRIVATE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
 
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET bgv_modified PROPERTY CXX_STANDARD 20)
endif()
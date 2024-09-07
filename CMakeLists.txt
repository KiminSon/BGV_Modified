# CMakeList.txt: bgv_modified에 대한 CMake 프로젝트, 여기에 소스를 포함하고
# 프로젝트 특정 논리를 정의합니다.
#
cmake_minimum_required (VERSION 3.8)

project ("bgv_modified")

# SEAL 라이브러리 경로 설정
set(SEAL_DIR "C:/Users/user/Desktop/mpc/SEAL/build")

# SEAL 라이브러리를 찾습니다. 이 줄을 추가하세요.
find_package(SEAL REQUIRED PATHS ${SEAL_DIR})

# 이 프로젝트의 실행 파일에 소스를 추가합니다.
add_executable (bgv_modified "main.cpp" "bgv_modified.h" "examples.h")

# SEAL 라이브러리를 bgv_modified 프로젝트에 링크합니다. 이 줄을 추가하세요.
target_link_libraries(bgv_modified PRIVATE SEAL::seal)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET bgv_modified PROPERTY CXX_STANDARD 20)
endif()

# TODO: 필요한 경우 테스트를 추가하고 대상을 설치합니다.

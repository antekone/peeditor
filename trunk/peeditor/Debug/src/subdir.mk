################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/Alloc.cc \
../src/ExportDirectory.cc \
../src/FlatAlloc.cc \
../src/ImportDirectory.cc \
../src/Instance.cc \
../src/Log.cc \
../src/MzHeader.cc \
../src/PeBuilder.cc \
../src/PeHeader.cc \
../src/RVAConverter.cc \
../src/Section.cc \
../src/Structure.cc \
../src/TraceCtx.cc \
../src/Utils.cc \
../src/main.cc \
../src/tests.cc 

OBJS += \
./src/Alloc.o \
./src/ExportDirectory.o \
./src/FlatAlloc.o \
./src/ImportDirectory.o \
./src/Instance.o \
./src/Log.o \
./src/MzHeader.o \
./src/PeBuilder.o \
./src/PeHeader.o \
./src/RVAConverter.o \
./src/Section.o \
./src/Structure.o \
./src/TraceCtx.o \
./src/Utils.o \
./src/main.o \
./src/tests.o 

CC_DEPS += \
./src/Alloc.d \
./src/ExportDirectory.d \
./src/FlatAlloc.d \
./src/ImportDirectory.d \
./src/Instance.d \
./src/Log.d \
./src/MzHeader.d \
./src/PeBuilder.d \
./src/PeHeader.d \
./src/RVAConverter.d \
./src/Section.d \
./src/Structure.d \
./src/TraceCtx.d \
./src/Utils.d \
./src/main.d \
./src/tests.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I"/home/antek/workspace/ped/headers" -O0 -g3 -gstabs+ -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '



sh clean.sh
cd bci && sh compile.sh && cd ../
INC="-Ibci/inc -Ibci/bitct/inc"
LIB="-Lbci/lib -Lbci/bitct/lib"
gcc -c -std=c11 $INC -o bca.o bca.c
gcc -std=c11 $INC $LIB -o bin/bca main.c bca.o -lmdl-bci -lmdl-bitct

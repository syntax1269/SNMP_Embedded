#ifndef Print_h
#define Print_h

#ifdef COMPILING_TESTS
#include <stddef.h>
#include <stdint.h>

class Print {
  public:
    virtual ~Print(){}
    virtual size_t write(uint8_t){ return 1; }
    size_t write(const char* str){
        if(!str) return 0;
        size_t n = 0;
        while(*str){ write((uint8_t)*str++); n++; }
        return n;
    }
    size_t write(const uint8_t* buf, size_t n){
        size_t i = 0;
        for(; i < n; i++) write(buf[i]);
        return i;
    }
    size_t print(const char* s){ return write(s); }
    size_t println(const char* s){ size_t n = write(s); write((uint8_t)'\r'); write((uint8_t)'\n'); return n+2; }
};
#endif

#endif

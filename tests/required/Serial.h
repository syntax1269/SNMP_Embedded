#ifndef Serial_h
#define Serial_h

#include <stdarg.h>
#include <stdio.h>

#ifdef COMPILING_TESTS
class HardwareSerial {
  public:
    int begin(int){return 0;};
    /* Real formatting so demo sketch banners (e.g. "SNMP_Embedded v%s") appear in
       host test runs (`make example`), letting you verify the version banner
       output before flashing to hardware. */
    int printf(const char* format, ...){
        va_list args;
        va_start(args, format);
        int n = vprintf(format, args);
        va_end(args);
        return n;
    };
    /* Templated no-ops: passing non-POD objects (e.g. IPAddress) through a
       variadic list is a hard error under -Wnon-pod-varargs, so print/println
       must not be variadic. Templates accept any single-argument call. */
    template <typename T> int print(const T&){ return 0; }
    template <typename T> int println(const T&){ return 0; }
    int println(){ return 0; }
};

HardwareSerial Serial;
#endif
#endif

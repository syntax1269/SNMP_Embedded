//
// Created by Aidan Cyr on 11/7/20.
//

#ifndef SNMP_EMBEDDED_MILLIS_H
#define SNMP_EMBEDDED_MILLIS_H

#ifdef COMPILING_TESTS
#define millis() (unsigned long)0
#endif

#endif //SNMP_EMBEDDED_MILLIS_H

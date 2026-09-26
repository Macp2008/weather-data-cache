// log_stub.cpp - Stub local para __android_log_print
// Esto evita depender de liblog.so (que no existe en Termux)
// En Android real, este archivo NO se usa (reemplazado por liblog del sistema)
#include <cstdarg>

extern "C" int __android_log_print(int /*prio*/, const char* /*tag*/, const char* /*fmt*/, ...) {
    return 0;
}

extern "C" int __android_log_vprint(int /*prio*/, const char* /*tag*/, const char* /*fmt*/, va_list /*args*/) {
    return 0;
}

extern "C" int __android_log_write(int /*prio*/, const char* /*tag*/, const char* /*text*/) {
    return 0;
}

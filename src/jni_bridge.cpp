#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>

#define TAG "CerebroBridge"

namespace cerebro {
struct Zona;
struct Resultado;
Resultado evaluarServicio(double precio, double distanciaRecogida,
                         bool tieneDescripcion, bool tieneParadas,
                         double latDestino, double lngDestino,
                         const std::vector<Zona> &zonas,
                         double precioMinimo, double precioMaximo,
                         double distanciaMaxima, bool rechazarParadas);
}

// Convierte jstring a std::string
static std::string jstringToString(JNIEnv *env, jstring jstr) {
    if (jstr == nullptr) return "";
    const char *chars = env->GetStringUTFChars(jstr, nullptr);
    std::string result(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

// Función JNI principal: evalúa un servicio
extern "C" JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_evaluarServicioNative(
        JNIEnv *env, jobject /* this */,
        jdouble precio,
        jdouble distanciaRecogida,
        jboolean tieneDescripcion,
        jboolean tieneParadas,
        jdouble latDestino,
        jdouble lngDestino,
        jstring zonasJson,
        jdouble precioMinimo,
        jdouble precioMaximo,
        jdouble distanciaMaxima,
        jboolean rechazarParadas) {

    __android_log_print(ANDROID_LOG_DEBUG, TAG,
                        "evaluarServicio: precio=%.0f, dist=%.0f",
                        precio, distanciaRecogida);

    std::vector<cerebro::Zona> zonas;
    // Las zonas se pasan luego como JSON; por ahora vector vacío
    (void)zonasJson;

    cerebro::Resultado r = cerebro::evaluarServicio(
            (double)precio, (double)distanciaRecogida,
            (bool)tieneDescripcion, (bool)tieneParadas,
            (double)latDestino, (double)lngDestino,
            zonas,
            (double)precioMinimo, (double)precioMaximo,
            (double)distanciaMaxima,
            (bool)rechazarParadas);

    // Devuelve un JSON simple
    std::string json = std::string("{\"aceptado\":") +
                       (r.aceptado ? "true" : "false") +
                       ",\"motivo\":\"" + r.motivo + "\"}";

    return env->NewStringUTF(json.c_str());
}

// Versión del cerebro
extern "C" JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_getVersionNative(
        JNIEnv *env, jobject) {
    return env->NewStringUTF("1.0.0");
}

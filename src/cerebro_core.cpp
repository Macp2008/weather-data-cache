// cerebro_core.cpp
// Lógica del "cerebro" - con getVersion + evaluarServicio
// Compilado a libcerebro.so, cifrado con AES-256-GCM y subido a GitHub Releases.

#include <jni.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstdio>
#include <android/log.h>

#define TAG "CerebroCore"

namespace cerebro {

struct Zona {
    std::string nombre;
    double lat;
    double lng;
    double radioMetros;
    bool esFavorita;
};

struct Resultado {
    bool aceptado;
    std::string motivo;
    double distanciaDestino;
};

static double distanciaMetros(double lat1, double lng1, double lat2, double lng2) {
    const double R = 6371000.0;
    double dLat = (lat2 - lat1) * M_PI / 180.0;
    double dLng = (lng2 - lng1) * M_PI / 180.0;
    double a = std::sin(dLat / 2) * std::sin(dLat / 2) +
               std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) *
               std::sin(dLng / 2) * std::sin(dLng / 2);
    return R * 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a));
}

static std::vector<Zona> parsearZonasJson(const std::string& json) {
    std::vector<Zona> zonas;
    if (json.empty() || json == "[]" || json == "null") return zonas;
    size_t pos = 0;
    while ((pos = json.find('{', pos)) != std::string::npos) {
        Zona z;
        z.esFavorita = false;
        z.radioMetros = 500.0;
        auto findNum = [&](const std::string& key, double& out) {
            size_t k = json.find("\"" + key + "\"", pos);
            if (k == std::string::npos) return false;
            size_t colon = json.find(':', k);
            if (colon == std::string::npos) return false;
            out = std::atof(json.c_str() + colon + 1);
            return true;
        };
        findNum("lat", z.lat);
        findNum("lng", z.lng);
        findNum("radio", z.radioMetros);
        size_t favPos = json.find("\"favorita\"", pos);
        if (favPos != std::string::npos && favPos < json.find('}', pos)) {
            size_t colon = json.find(':', favPos);
            z.esFavorita = (json.substr(colon + 1, 10).find("true") != std::string::npos);
        }
        zonas.push_back(z);
        pos = json.find('}', pos);
        if (pos == std::string::npos) break;
        pos++;
    }
    return zonas;
}

static Resultado evaluarServicio(
    double precio, double distanciaRecogida, bool tieneDescripcion,
    bool tieneParadas, double latDestino, double lngDestino,
    const std::string& zonasJson, double precioMinimo, double precioMaximo,
    double distanciaMaxima, bool rechazarParadas
) {
    Resultado r;
    r.aceptado = false;
    r.motivo = "desconocido";
    if (!tieneDescripcion) { r.motivo = "sin_descripcion"; return r; }
    if (rechazarParadas && tieneParadas) { r.motivo = "tiene_paradas"; return r; }
    if (precioMinimo > 0.0 && precio < precioMinimo) { r.motivo = "precio_bajo_minimo"; return r; }
    if (precioMaximo > 0.0 && precio > precioMaximo) { r.motivo = "precio_sobre_maximo"; return r; }
    if (distanciaMaxima > 0.0 && distanciaRecogida > distanciaMaxima) { r.motivo = "demasiado_lejos"; return r; }
    if (latDestino != 0.0 && lngDestino != 0.0) {
        std::vector<Zona> zonas = parsearZonasJson(zonasJson);
        for (const auto& z : zonas) {
            double d = distanciaMetros(z.lat, z.lng, latDestino, lngDestino);
            if (d <= z.radioMetros) {
                if (!z.esFavorita) { r.motivo = "zona_bloqueada"; return r; }
                r.aceptado = true;
                r.motivo = "zona_favorita";
                r.distanciaDestino = d;
                return r;
            }
        }
    }
    r.aceptado = true;
    r.motivo = "ok";
    return r;
}

} // namespace cerebro

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_getVersion(JNIEnv *env, jobject) {
    return env->NewStringUTF("v1.0.2");
}

JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_evaluarServicioNative(
    JNIEnv *env, jobject,
    jdouble precio, jdouble distanciaRecogida,
    jboolean tieneDescripcion, jboolean tieneParadas,
    jdouble latDestino, jdouble lngDestino,
    jstring zonasJson,
    jdouble precioMinimo, jdouble precioMaximo,
    jdouble distanciaMaxima, jboolean rechazarParadas
) {
    using namespace cerebro;
    const char* zonasChars = env->GetStringUTFChars(zonasJson, nullptr);
    std::string zonasStr = (zonasChars != nullptr) ? zonasChars : "[]";
    env->ReleaseStringUTFChars(zonasJson, zonasChars);
    Resultado r = evaluarServicio(
        (double)precio, (double)distanciaRecogida,
        (bool)tieneDescripcion, (bool)tieneParadas,
        (double)latDestino, (double)lngDestino, zonasStr,
        (double)precioMinimo, (double)precioMaximo,
        (double)distanciaMaxima, (bool)rechazarParadas
    );
    char buffer[512];
    std::snprintf(buffer, sizeof(buffer),
        "{\"aceptado\":%s,\"motivo\":\"%s\",\"distancia\":%.2f}",
        r.aceptado ? "true" : "false", r.motivo.c_str(), r.distanciaDestino);
    return env->NewStringUTF(buffer);
}

}

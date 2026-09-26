#include <jni.h>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
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

static double distanciaMetros(double lat1, double lng1,
                              double lat2, double lng2) {
    const double R = 6371000.0;
    double dLat = (lat2 - lat1) * M_PI / 180.0;
    double dLng = (lng2 - lng1) * M_PI / 180.0;
    double a = std::sin(dLat / 2) * std::sin(dLat / 2) +
               std::cos(lat1 * M_PI / 180.0) *
               std::cos(lat2 * M_PI / 180.0) *
               std::sin(dLng / 2) * std::sin(dLng / 2);
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a));
    return R * c;
}

static bool estaEnZonaFavorita(double lat, double lng,
                               const std::vector<Zona> &zonas) {
    for (const auto &z : zonas) {
        if (!z.esFavorita) continue;
        if (distanciaMetros(lat, lng, z.lat, z.lng) <= z.radioMetros)
            return true;
    }
    return false;
}

static bool estaEnZonaBloqueada(double lat, double lng,
                                const std::vector<Zona> &zonas) {
    for (const auto &z : zonas) {
        if (z.esFavorita) continue;
        if (distanciaMetros(lat, lng, z.lat, z.lng) <= z.radioMetros)
            return true;
    }
    return false;
}

Resultado evaluarServicio(double precio,
                         double distanciaRecogida,
                         bool tieneDescripcion,
                         bool tieneParadas,
                         double latDestino,
                         double lngDestino,
                         const std::vector<Zona> &zonas,
                         double precioMinimo,
                         double precioMaximo,
                         double distanciaMaxima,
                         bool rechazarParadas) {

    Resultado r{};
    r.aceptado = true;
    r.motivo = "ok";
    r.distanciaDestino = 0.0;

    if (precioMinimo > 0 && precio < precioMinimo) {
        r.aceptado = false;
        r.motivo = "precio_bajo_minimo";
        return r;
    }

    if (precioMaximo > 0 && precio > precioMaximo) {
        r.aceptado = false;
        r.motivo = "precio_sobre_maximo";
        return r;
    }

    if (distanciaMaxima > 0 && distanciaRecogida > distanciaMaxima) {
        r.aceptado = false;
        r.motivo = "distancia_excedida";
        return r;
    }

    if (rechazarParadas && tieneParadas) {
        r.aceptado = false;
        r.motivo = "multiples_paradas";
        return r;
    }

    if (estaEnZonaBloqueada(latDestino, lngDestino, zonas)) {
        r.aceptado = false;
        r.motivo = "zona_bloqueada_mapa";
        return r;
    }

    return r;
}

} // namespace cerebro

extern "C" JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_getVersion(JNIEnv *env, jobject) {
    return env->NewStringUTF("1.0.0");
}

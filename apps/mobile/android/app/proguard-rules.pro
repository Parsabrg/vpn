# hev-socks5-tunnel registers its JNI methods against this class by name
# (compiled in; see third_party_src/vendor_plugin.py). Renamed by R8, its
# JNI_OnLoad finds nothing, the library fails to load, and the VPN comes up
# with nothing reading its interface. Seen on a phone with the first release
# build.
-keep class dev.amirzr.flutter_v2ray_client.v2ray.services.TProxyService {
    native <methods>;
}

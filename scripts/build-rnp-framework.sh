#!/bin/bash
# scripts/build-rnp-framework.sh
set -euo pipefail

RNP_REF="${RNP_REF:-v0.18.1}"
BOTAN_VERSION="${BOTAN_VERSION:-3.10.0}"
JSONC_TAG="${JSONC_TAG:-json-c-0.18-20240915}"
SEXPP_REF="${SEXPP_REF:-c641a2f36520bab783657a58650d9fda548b9dec}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/Vendor/RNPFramework.xcframework}"
WORK_DIR="${WORK_DIR:-${REPO_ROOT}/.build/framework-work}"
SIGN_IDENTITY="${SIGN_IDENTITY:-}"            # optional, e.g. "Developer ID Application: ..."
USE_PREFIX="${USE_PREFIX:-}"                  # optional fast path: local prefix with prebuilt static libs

mkdir -p "${WORK_DIR}"
mkdir -p "${REPO_ROOT}/Vendor/pkgconfig"

# ------------------------------------------------------------------
# Fast path: assemble a framework from a local prefix (dev only).
# Expected layout:
#   <prefix>/include/rnp/*.h   (public + generated headers)
#   <prefix>/lib/librnp.a      (static rnp)
#   <prefix>/src/libsexpp/libsexpp.a  (or lib/libsexpp.a)
# plus homebrew static libs for botan + json-c.
# ------------------------------------------------------------------
if [[ -n "${USE_PREFIX}" ]]; then
    echo "Using local prefix: ${USE_PREFIX}"
    PREFIX="$(cd "${USE_PREFIX}" && pwd)"
    HEADERS_DIR="${PREFIX}/include"
    RNP_A="${RNP_A:-${PREFIX}/lib/librnp.a}"
    SEXPP_A="${SEXPP_A:-${PREFIX}/src/libsexpp/libsexpp.a}"
    if [[ ! -f "${SEXPP_A}" ]]; then
        SEXPP_A="${PREFIX}/lib/libsexpp.a"
    fi
    BOTAN_A="${BOTAN_A:-/opt/homebrew/opt/botan/lib/libbotan-3.a}"
    JSONC_A="${JSONC_A:-/opt/homebrew/opt/json-c/lib/libjson-c.a}"

    for f in "${RNP_A}" "${SEXPP_A}" "${BOTAN_A}" "${JSONC_A}"; do
        [[ -f "${f}" ]] || { echo "Missing static lib: ${f}" >&2; exit 1; }
    done
    [[ -d "${HEADERS_DIR}/rnp" ]] || { echo "Missing headers: ${HEADERS_DIR}/rnp" >&2; exit 1; }

    ARCHS="$(lipo -info "${RNP_A}" | awk '{print $NF}')"
    echo "Detected architecture(s): ${ARCHS}"

    BUILD_DIR="${WORK_DIR}/fast"
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"

    SYMS="${BUILD_DIR}/exported_symbols"
    nm -g "${RNP_A}" 2>/dev/null | awk '/ T _rnp_/ {print $3}' | sort -u > "${SYMS}"
    if [[ ! -s "${SYMS}" ]]; then
        echo "Could not extract rnp symbols; falling back to all symbols" >&2
        echo "*" > "${SYMS}"
    fi

    FW_DIR="${BUILD_DIR}/RNPFramework.framework"
    VERSIONS="${FW_DIR}/Versions/A"
    mkdir -p "${VERSIONS}/Headers/rnp" "${VERSIONS}/Modules" "${VERSIONS}/Resources"
    cp "${HEADERS_DIR}/rnp"/*.h "${VERSIONS}/Headers/rnp/"

    # rnp's own headers do `#include <rnp/XXX.h>` internally. Those angled
    # includes can't resolve when this framework is imported as a binary
    # target (no -I points at our Headers/). Rewrite them to quoted includes
    # so they resolve relative to the headers' own directory.
    sed -i.bak -E 's/#(include|import) <rnp\/([^>]+)>/#\1 "\2"/g' "${VERSIONS}/Headers/rnp/"*.h
    rm -f "${VERSIONS}/Headers/rnp/"*.h.bak

    cat > "${VERSIONS}/Modules/module.modulemap" <<EOF
framework module RNPFramework {
    umbrella header "RNPFramework.h"
    export *
}
EOF

    cat > "${VERSIONS}/Headers/RNPFramework.h" <<EOF
#import "rnp/rnp.h"
#import "rnp/rnp_err.h"
#import "rnp/rnp_export.h"
#import "rnp/rnp_ver.h"
EOF

    # Minimal Info.plist
    cat > "${VERSIONS}/Resources/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>RNPFramework</string>
    <key>CFBundleIdentifier</key>
    <string>com.rnpgp.RNPFramework</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>RNPFramework</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>${RNP_REF#v}</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
EOF

    clang -dynamiclib \
        -arch "${ARCHS}" \
        -mmacosx-version-min=12.0 \
        -o "${VERSIONS}/RNPFramework" \
        -Wl,-all_load "${RNP_A}" "${SEXPP_A}" "${BOTAN_A}" "${JSONC_A}" \
        -lz -lbz2 -lc++ \
        -Wl,-dead_strip \
        -Wl,-exported_symbols_list,"${SYMS}" \
        -install_name "@rpath/RNPFramework.framework/Versions/A/RNPFramework"

    ln -sfn A "${FW_DIR}/Versions/Current"
    ln -sfn Versions/Current/RNPFramework "${FW_DIR}/RNPFramework"
    ln -sfn Versions/Current/Headers "${FW_DIR}/Headers"
    ln -sfn Versions/Current/Modules "${FW_DIR}/Modules"
    ln -sfn Versions/Current/Resources "${FW_DIR}/Resources"

    if [[ -n "${SIGN_IDENTITY}" ]]; then
        codesign --sign "${SIGN_IDENTITY}" --force --timestamp=none "${FW_DIR}"
    else
        codesign --sign - --force "${FW_DIR}"
    fi

    rm -rf "${OUT_DIR}"
    xcodebuild -create-xcframework -framework "${FW_DIR}" -output "${OUT_DIR}"

    # Generate pkg-config file pointing at the concrete slice.
    SLICE_DIR="$(find "${OUT_DIR}" -maxdepth 2 -name 'RNPFramework.framework' | head -n1)"
    FRAMEWORK_DIR="$(dirname "${SLICE_DIR}")"
    cat > "${REPO_ROOT}/Vendor/pkgconfig/librnp.pc" <<EOF
prefix=\${pcfiledir}/../RNPFramework.xcframework/macos-arm64_x86_64/RNPFramework.framework
exec_prefix=\${prefix}
libdir=\${prefix}
includedir=\${prefix}/Headers

Name: rnp
Description: RNPFramework vendored for RnpMail
Version: ${RNP_REF#v}
Libs: -F\${pcfiledir}/../RNPFramework.xcframework/macos-arm64_x86_64 -framework RNPFramework
Cflags: -I\${includedir}
EOF

    echo "Wrote ${OUT_DIR}"
    echo "Wrote ${REPO_ROOT}/Vendor/pkgconfig/librnp.pc"
    exit 0
fi

# ------------------------------------------------------------------
# Full source build (fresh-clone path). Downloads tarballs, builds
# universal arm64+x86_64 static libraries, combines into one dylib.
# ------------------------------------------------------------------
SRC_DIR="${WORK_DIR}/src"
mkdir -p "${SRC_DIR}"

# Download helpers
require_hash() {
    local file="$1" hashfile="$2"
    local expected="$(cat "${hashfile}" | awk '{print $1}')"
    local actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    if [[ "${expected}" != "${actual}" ]]; then
        echo "Hash mismatch for ${file}: expected ${expected}, got ${actual}" >&2
        exit 1
    fi
}

download() {
    local url="$1" dest="$2"
    if [[ ! -f "${dest}" ]]; then
        echo "Downloading ${url}"
        curl -fsSL "${url}" -o "${dest}"
    fi
}

RNP_TARBALL="${SRC_DIR}/rnp-${RNP_REF}.tar.gz"
BOTAN_TARBALL="${SRC_DIR}/Botan-${BOTAN_VERSION}.tar.gz"
JSONC_TARBALL="${SRC_DIR}/${JSONC_TAG}.tar.gz"

HASH_DIR="${SCRIPT_DIR}"
mkdir -p "${HASH_DIR}"

download "https://github.com/rnpgp/rnp/archive/refs/tags/${RNP_REF}.tar.gz" "${RNP_TARBALL}"
download "https://github.com/randombit/botan/archive/refs/tags/${BOTAN_VERSION}.tar.gz" "${BOTAN_TARBALL}"
download "https://github.com/json-c/json-c/archive/refs/tags/${JSONC_TAG}.tar.gz" "${JSONC_TARBALL}"

# Verify or record pinned hashes. If a hash file already exists, the tarball
# must match it; otherwise compute the hash from the downloaded tarball.
for pair in "rnp-${RNP_REF}.tar.gz:${HASH_DIR}/rnp-${RNP_REF}.sha256" \
            "Botan-${BOTAN_VERSION}.tar.gz:${HASH_DIR}/Botan-${BOTAN_VERSION}.sha256" \
            "${JSONC_TAG}.tar.gz:${HASH_DIR}/${JSONC_TAG}.sha256"; do
    file="${SRC_DIR}/${pair%%:*}"
    hashfile="${pair##*:}"
    if [[ -f "${hashfile}" ]]; then
        require_hash "${file}" "${hashfile}"
    else
        echo "Recording hash: ${hashfile}"
        shasum -a 256 "${file}" > "${hashfile}"
    fi
done

# Extract
RNP_SRC="${SRC_DIR}/rnp-${RNP_REF#v}"
BOTAN_SRC="${SRC_DIR}/botan-${BOTAN_VERSION}"
JSONC_SRC="${SRC_DIR}/json-c-${JSONC_TAG}"
rm -rf "${RNP_SRC}" "${BOTAN_SRC}" "${JSONC_SRC}"
tar -xzf "${RNP_TARBALL}" -C "${SRC_DIR}"
tar -xzf "${BOTAN_TARBALL}" -C "${SRC_DIR}"
tar -xzf "${JSONC_TARBALL}" -C "${SRC_DIR}"

# sexpp submodule (full clone so an arbitrary commit ref is reachable)
rm -rf "${RNP_SRC}/src/libsexpp"
git clone "https://github.com/rnpgp/sexpp.git" "${RNP_SRC}/src/libsexpp"
git -C "${RNP_SRC}/src/libsexpp" checkout "${SEXPP_REF}"

# rnp forces C++ symbol visibility to hidden for static builds, which prevents
# the public FFI symbols from being re-exported from our framework. Override it.
sed -i.bak 's/CXX_VISIBILITY_PRESET hidden/CXX_VISIBILITY_PRESET default/' \
    "${RNP_SRC}/src/lib/CMakeLists.txt"
rm -f "${RNP_SRC}/src/lib/CMakeLists.txt.bak"

INSTALL_PREFIX="${WORK_DIR}/install"
mkdir -p "${INSTALL_PREFIX}"

# Build Botan static for each arch
build_botan() {
    local arch="$1"
    local build="${BOTAN_SRC}/build-${arch}"
    local prefix="${INSTALL_PREFIX}/botan-${arch}"
    if [[ -f "${prefix}/lib/libbotan-3.a" ]]; then
        echo "Botan ${arch} already built; skipping"
        return
    fi
    rm -rf "${build}" "${prefix}"
    mkdir -p "${build}"

    local extra_cxxflags="-mmacosx-version-min=12.0"
    local extra_ldflags="-mmacosx-version-min=12.0"
    local cc_bin="clang"
    local cxx_bin="clang++"

    if [[ "${arch}" == "x86_64" ]]; then
        # On Apple Silicon we are building a cross-arch static library. Botan's
        # compiler probe defaults to the host (arm64), so inject -arch x86_64
        # via wrapper scripts that configure.py uses for both probing and
        # compilation.
        extra_cxxflags="-arch x86_64 -mmacosx-version-min=12.0"
        extra_ldflags="-arch x86_64 -mmacosx-version-min=12.0"
        local wrap_dir="${WORK_DIR}/clang-wrap-${arch}"
        rm -rf "${wrap_dir}"
        mkdir -p "${wrap_dir}"
        cc_bin="${wrap_dir}/clang"
        cxx_bin="${wrap_dir}/clang++"
        cat > "${cc_bin}" <<EOF
#!/bin/sh
exec /usr/bin/clang -arch x86_64 -mmacosx-version-min=12.0 "\$@"
EOF
        cat > "${cxx_bin}" <<EOF
#!/bin/sh
exec /usr/bin/clang++ -arch x86_64 -mmacosx-version-min=12.0 "\$@"
EOF
        chmod +x "${cc_bin}" "${cxx_bin}"
    fi

    # Avoid picking up Homebrew LDFLAGS/CPPFLAGS/CXXFLAGS that would leak
    # into the static lib or select the wrong architecture.
    env -u LDFLAGS -u CPPFLAGS -u CXXFLAGS \
    python3 "${BOTAN_SRC}/configure.py" \
        --prefix="${prefix}" \
        --os=macos \
        --cpu="${arch}" \
        --disable-shared \
        --without-documentation \
        --build-targets="static" \
        --cc=clang \
        --cc-bin="${cc_bin}" \
        --with-build-dir="${build}" \
        --cxxflags="${extra_cxxflags}" \
        --ldflags="${extra_ldflags}"
    make -C "${build}" -j"$(sysctl -n hw.ncpu)"
    make -C "${build}" install
}

# Build json-c static for each arch
build_jsonc() {
    local arch="$1"
    local build="${JSONC_SRC}/build-${arch}"
    local prefix="${INSTALL_PREFIX}/jsonc-${arch}"
    if [[ -f "${prefix}/lib/libjson-c.a" ]]; then
        echo "json-c ${arch} already built; skipping"
        return
    fi
    rm -rf "${build}" "${prefix}"
    cmake -S "${JSONC_SRC}" -B "${build}" \
        -DCMAKE_INSTALL_PREFIX="${prefix}" \
        -DCMAKE_OSX_ARCHITECTURES="${arch}" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build "${build}" -j"$(sysctl -n hw.ncpu)"
    cmake --install "${build}"
}

# Build rnp static for each arch
build_rnp() {
    local arch="$1"
    local build="${RNP_SRC}/build-${arch}"
    local prefix="${INSTALL_PREFIX}/rnp-${arch}"
    if [[ -f "${prefix}/lib/librnp.a" ]]; then
        echo "rnp ${arch} already built; skipping"
        return
    fi
    rm -rf "${build}" "${prefix}"
    cmake -S "${RNP_SRC}" -B "${build}" \
        -DCMAKE_INSTALL_PREFIX="${prefix}" \
        -DCMAKE_OSX_ARCHITECTURES="${arch}" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
        -DCMAKE_C_VISIBILITY_PRESET=default \
        -DCMAKE_CXX_VISIBILITY_PRESET=default \
        -DCRYPTO_BACKEND=botan3 \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF \
        -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}/botan-${arch};${INSTALL_PREFIX}/jsonc-${arch}"
    cmake --build "${build}" -j"$(sysctl -n hw.ncpu)"
    cmake --install "${build}"
}

build_botan arm64
build_jsonc arm64
build_rnp arm64

build_botan x86_64
build_jsonc x86_64
build_rnp x86_64

# Combine per-arch static libs into fat libs
FAT_DIR="${WORK_DIR}/fat"
mkdir -p "${FAT_DIR}"
lipo -create \
    "${INSTALL_PREFIX}/rnp-arm64/lib/librnp.a" \
    "${INSTALL_PREFIX}/rnp-x86_64/lib/librnp.a" \
    -output "${FAT_DIR}/librnp.a"
lipo -create \
    "${INSTALL_PREFIX}/rnp-arm64/lib/libsexpp.a" \
    "${INSTALL_PREFIX}/rnp-x86_64/lib/libsexpp.a" \
    -output "${FAT_DIR}/libsexpp.a"
lipo -create \
    "${INSTALL_PREFIX}/botan-arm64/lib/libbotan-3.a" \
    "${INSTALL_PREFIX}/botan-x86_64/lib/libbotan-3.a" \
    -output "${FAT_DIR}/libbotan-3.a"
lipo -create \
    "${INSTALL_PREFIX}/jsonc-arm64/lib/libjson-c.a" \
    "${INSTALL_PREFIX}/jsonc-x86_64/lib/libjson-c.a" \
    -output "${FAT_DIR}/libjson-c.a"

# Use arm64 headers (same content for both archs)
HEADERS_DIR="${INSTALL_PREFIX}/rnp-arm64/include"

# Build universal framework using the same logic as the fast path,
# but with -arch arm64 -arch x86_64.
BUILD_DIR="${WORK_DIR}/source"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

SYMS="${BUILD_DIR}/exported_symbols"
# rnp ships a wildcard symbol list: export every _rnp_* symbol and nothing else.
# This keeps Botan/json-c/sexpp internals private while exposing the public FFI.
cp "${RNP_SRC}/src/lib/librnp.symbols" "${SYMS}"
if [[ ! -s "${SYMS}" ]]; then
    echo "Could not locate rnp symbol list; falling back to all symbols" >&2
    echo "*" > "${SYMS}"
fi

FW_DIR="${BUILD_DIR}/RNPFramework.framework"
VERSIONS="${FW_DIR}/Versions/A"
mkdir -p "${VERSIONS}/Headers/rnp" "${VERSIONS}/Modules" "${VERSIONS}/Resources"
cp "${HEADERS_DIR}/rnp"/*.h "${VERSIONS}/Headers/rnp/"

# rnp's own headers do `#include <rnp/XXX.h>` internally. Those angled
# includes can't resolve when this framework is imported as a binary
# target (no -I points at our Headers/). Rewrite them to quoted includes
# so they resolve relative to the headers' own directory.
sed -i.bak -E 's/#(include|import) <rnp\/([^>]+)>/#\1 "\2"/g' "${VERSIONS}/Headers/rnp/"*.h
rm -f "${VERSIONS}/Headers/rnp/"*.h.bak

cat > "${VERSIONS}/Modules/module.modulemap" <<EOF
framework module RNPFramework {
    umbrella header "RNPFramework.h"
    export *
}
EOF

cat > "${VERSIONS}/Headers/RNPFramework.h" <<EOF
#import "rnp/rnp.h"
#import "rnp/rnp_err.h"
#import "rnp/rnp_export.h"
#import "rnp/rnp_ver.h"
EOF

cat > "${VERSIONS}/Resources/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>RNPFramework</string>
    <key>CFBundleIdentifier</key>
    <string>com.rnpgp.RNPFramework</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>RNPFramework</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>${RNP_REF#v}</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
EOF

clang -dynamiclib \
    -arch arm64 -arch x86_64 \
    -mmacosx-version-min=12.0 \
    -o "${VERSIONS}/RNPFramework" \
    -Wl,-all_load \
        "${FAT_DIR}/librnp.a" \
        "${FAT_DIR}/libsexpp.a" \
        "${FAT_DIR}/libbotan-3.a" \
        "${FAT_DIR}/libjson-c.a" \
    -lz -lbz2 -lc++ \
    -Wl,-dead_strip \
    -Wl,-exported_symbols_list,"${SYMS}" \
    -install_name "@rpath/RNPFramework.framework/Versions/A/RNPFramework"

ln -sfn A "${FW_DIR}/Versions/Current"
ln -sfn Versions/Current/RNPFramework "${FW_DIR}/RNPFramework"
ln -sfn Versions/Current/Headers "${FW_DIR}/Headers"
ln -sfn Versions/Current/Modules "${FW_DIR}/Modules"
ln -sfn Versions/Current/Resources "${FW_DIR}/Resources"

if [[ -n "${SIGN_IDENTITY}" ]]; then
    codesign --sign "${SIGN_IDENTITY}" --force --timestamp=none "${FW_DIR}"
else
    codesign --sign - --force "${FW_DIR}"
fi

rm -rf "${OUT_DIR}"
xcodebuild -create-xcframework -framework "${FW_DIR}" -output "${OUT_DIR}"

SLICE_DIR="$(find "${OUT_DIR}" -maxdepth 2 -name 'RNPFramework.framework' | head -n1)"
FRAMEWORK_DIR="$(dirname "${SLICE_DIR}")"
cat > "${REPO_ROOT}/Vendor/pkgconfig/librnp.pc" <<EOF
prefix=\${pcfiledir}/../RNPFramework.xcframework/macos-arm64_x86_64/RNPFramework.framework
exec_prefix=\${prefix}
libdir=\${prefix}
includedir=\${prefix}/Headers

Name: rnp
Description: RNPFramework vendored for RnpMail
Version: ${RNP_REF#v}
Libs: -F\${pcfiledir}/../RNPFramework.xcframework/macos-arm64_x86_64 -framework RNPFramework
Cflags: -I\${includedir}
EOF

echo "Wrote ${OUT_DIR}"
echo "Wrote ${REPO_ROOT}/Vendor/pkgconfig/librnp.pc"

# Smoke-test: the framework must export at least a few public rnp symbols.
if ! nm -g "${SLICE_DIR}/RNPFramework" 2>/dev/null | grep "T _rnp_ffi_create" >/dev/null 2>&1; then
    echo "ERROR: framework does not appear to export rnp symbols" >&2
    exit 1
fi
